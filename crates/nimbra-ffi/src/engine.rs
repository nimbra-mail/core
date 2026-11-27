//! `Engine`: the accounts on this device and everything done with their mail.
//!
//! **Every method blocks.** Each may wait on the network, the disk or the Keychain, some
//! for many seconds (marked "Network" below), so Swift calls them from a background task,
//! never the main actor. The engine is safe to call from several threads at once.
//!
//! It keeps one connection and one encrypted store per account, opened on first use. It
//! keeps no timers: the app decides when to check for mail, wake snoozes, send what is due
//! and deliver a message once its undo time is over.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use nimbra_core::imap_mail::Credential;
use nimbra_core::settings::{AccountRef, Settings};
use nimbra_core::store::Store;
use nimbra_core::{
    accounts, blocking, contacts, discover, gmail, imap_mail, listing, mail, microsoft, paths,
    sending, servers, settings, signature, snooze, store,
};

use crate::error::{NimbraError, Result};
use crate::secrets::{self, SecretStore};
use crate::types::*;

pub(crate) fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// One account's connection and store.
pub(crate) struct Open {
    pub(crate) client: Arc<mail::Client>,
    pub(crate) store: Arc<Store>,
}

/// A sign-in the browser has not come back from yet.
enum Pending {
    Google {
        /// The account it signs in to: a new id, or the account signed in to again.
        account: String,
        existing: bool,
        authorization: gmail::Authorization,
    },
    Microsoft {
        /// The account signed in to again, if it is one.
        existing: Option<String>,
        authorization: microsoft::Authorization,
    },
}

#[derive(uniffi::Object)]
pub struct Engine {
    google: Option<gmail::Config>,
    microsoft: Option<microsoft::Config>,
    settings: Mutex<Settings>,
    open: Mutex<HashMap<String, Arc<Open>>>,
    pending: Mutex<HashMap<String, Pending>>,
    /// Numbers the messages handed to `queue_send` (the core's "composer").
    pub(crate) sends: Mutex<u64>,
    /// Messages that wait for the connection, by account: sent by `catch_up`.
    pub(crate) waiting: Mutex<HashMap<String, Vec<Arc<sending::Job>>>>,
}

#[uniffi::export]
impl Engine {
    /// Opens the engine over the settings in `data_dir`, where it also keeps each account's
    /// encrypted store; `cache_dir` holds what can be downloaded again. Both are the app's
    /// own absolute folders (on iOS, its Application Support and Caches): there is no
    /// default, so the engine never reads or writes another app's files. One pair per
    /// process. `secrets` is the app's Keychain, which the engine then uses for every
    /// secret (`SecretStore`); without it, the system's Keychain is used as it is. Disk.
    #[uniffi::constructor]
    pub fn new(
        config: EngineConfig,
        data_dir: String,
        cache_dir: String,
        secrets: Option<Arc<dyn SecretStore>>,
    ) -> Result<Arc<Self>> {
        let (data, cache) = (data_dir.trim(), cache_dir.trim());
        if data.is_empty() || cache.is_empty() {
            return Err(NimbraError::invalid(
                "The engine needs its data and cache folders.",
            ));
        }
        paths::set(std::path::Path::new(data), std::path::Path::new(cache))
            .map_err(|e| NimbraError::invalid(e.to_string()))?;
        if let Some(store) = secrets {
            secrets::install(store);
        }
        let google = match config.google_client_id.as_deref() {
            Some(id) => Some(
                gmail::Config::new(id, config.google_client_secret.as_deref())
                    .ok_or_else(|| NimbraError::invalid("The Google client id is empty."))?,
            ),
            None => None,
        };
        let microsoft =
            match config.microsoft_client_id.as_deref() {
                Some(id) => Some(microsoft::Config::new(id).ok_or_else(|| {
                    NimbraError::invalid("The Microsoft client id is not a GUID.")
                })?),
                None => None,
            };
        let mut settings = settings::load();
        settings.migrate();
        Ok(Arc::new(Engine {
            google,
            microsoft,
            settings: Mutex::new(settings),
            open: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            sends: Mutex::new(0),
            waiting: Mutex::new(HashMap::new()),
        }))
    }

    /// Writes what is waiting to be written (settings, stores), for a few seconds at most:
    /// call it when the app goes to the background. Whether everything is on disk. Disk.
    pub fn flush(&self) -> bool {
        let settings = settings::flush();
        let stores = store::flush(std::time::Instant::now() + std::time::Duration::from_secs(3));
        settings && stores
    }

    // -------------------------------------------------------------- accounts

    /// The accounts on this device, in their order. Memory only.
    pub fn accounts(&self) -> Vec<Account> {
        let settings = locked(&self.settings);
        let default = settings.default_account().map(String::from);
        settings
            .accounts
            .iter()
            .map(|account| Account {
                id: account.id.clone(),
                email: account.email.clone(),
                kind: kind_of(account),
                is_default: default.as_deref() == Some(account.id.as_str()),
            })
            .collect()
    }

    /// The account new messages are from unless another is picked. Disk.
    pub fn set_default_account(&self, account_id: String) -> Result<()> {
        self.change_settings(|settings| {
            if !settings.accounts.iter().any(|a| a.id == account_id) {
                return Err(NimbraError::invalid("There is no such account."));
            }
            settings.default_account = Some(account_id);
            Ok(())
        })
    }

    /// Starts a Google sign-in that comes back to `redirect_uri` (for an iOS client,
    /// `com.googleusercontent.apps.<id>:/oauth2redirect`). `account_id` signs in to that
    /// account again: no other Google account is then accepted. `full_access` also asks
    /// for deleting for good. Memory only: the browser talks to Google.
    pub fn begin_google_sign_in(
        &self,
        redirect_uri: String,
        account_id: Option<String>,
        full_access: bool,
    ) -> Result<SignInRequest> {
        let config = self.google()?;
        let (account, expected) = match account_id {
            Some(id) => {
                let email = self
                    .account(&id)?
                    .filter(|a| kind_of(a) == AccountKind::Gmail)
                    .map(|a| a.email)
                    .ok_or_else(|| NimbraError::invalid("That is not a Gmail account here."))?;
                (id, Some(email))
            }
            None => (mail::new_account_id()?, None),
        };
        let (authorization, url) =
            gmail::Authorization::start(config, &redirect_uri, full_access, expected.as_deref())?;
        let existing = expected.is_some();
        self.pend(
            url,
            Pending::Google {
                account,
                existing,
                authorization,
            },
        )
    }

    /// Finishes a Google sign-in with the address the browser came back to, and keeps the
    /// account (its sign-in in the Keychain). Network.
    pub fn finish_google_sign_in(
        &self,
        request_id: String,
        callback_url: String,
    ) -> Result<Account> {
        let Some(Pending::Google {
            account,
            existing,
            authorization,
        }) = self.take_pending(&request_id, true)
        else {
            return Err(NimbraError::invalid(
                "That sign-in is over. Please start again.",
            ));
        };
        let config = self.google()?;
        let client = authorization
            .finish(config, &account, &callback_url)
            .map_err(|e| {
                let refused = NimbraError::from(e);
                if existing {
                    refused.for_account(&account)
                } else {
                    refused
                }
            })?;
        if existing {
            // A new sign-in for the same account: the connection opens again with it.
            locked(&self.open).remove(&account);
            return self
                .accounts()
                .into_iter()
                .find(|a| a.id == account)
                .ok_or_else(|| NimbraError::invalid("That account was removed meanwhile."));
        }
        let email = match mail::Provider::profile(&client) {
            Ok((email, _)) => email,
            Err(error) => {
                gmail::forget_refresh_token(&account);
                return Err(error.into());
            }
        };
        self.keep_account(AccountRef {
            id: account,
            email,
            servers: None,
            oauth: None,
        })
    }

    /// Starts a Microsoft sign-in that comes back to `redirect_uri` (for iOS,
    /// `msauth.<bundle id>://auth`, as registered). `account_id` signs in to that account
    /// again. `hint` is an address to fill in. Memory only: the browser talks to Microsoft.
    pub fn begin_microsoft_sign_in(
        &self,
        redirect_uri: String,
        account_id: Option<String>,
        hint: Option<String>,
    ) -> Result<SignInRequest> {
        let config = self.microsoft()?;
        let hint = match &account_id {
            Some(id) => Some(
                self.account(id)?
                    .filter(|a| kind_of(a) == AccountKind::Microsoft)
                    .map(|a| a.email)
                    .ok_or_else(|| NimbraError::invalid("That is not a Microsoft account here."))?,
            ),
            None => hint,
        };
        let (authorization, url) =
            microsoft::Authorization::start(config, &redirect_uri, hint.as_deref())?;
        self.pend(
            url,
            Pending::Microsoft {
                existing: account_id,
                authorization,
            },
        )
    }

    /// Finishes a Microsoft sign-in, checks that the mailbox lets Nimbra in over IMAP, and
    /// keeps the account. Network.
    pub fn finish_microsoft_sign_in(
        &self,
        request_id: String,
        callback_url: String,
    ) -> Result<Account> {
        let Some(Pending::Microsoft {
            existing,
            authorization,
        }) = self.take_pending(&request_id, false)
        else {
            return Err(NimbraError::invalid(
                "That sign-in is over. Please start again.",
            ));
        };
        let config = self.microsoft()?;
        let named = |error: anyhow::Error| match &existing {
            Some(id) => NimbraError::from(error).for_account(id),
            None => NimbraError::from(error),
        };
        let (email, tokens) = authorization.finish(config, &callback_url).map_err(named)?;
        if let Some(id) = &existing {
            let expected = self
                .account(id)?
                .map(|a| a.email)
                .ok_or_else(|| NimbraError::invalid("That account was removed meanwhile."))?;
            microsoft::check_same_account(&expected, &email)?;
        } else if self.has_email(&email) {
            return Err(already_here(&email));
        }
        let servers = microsoft::servers(&email);
        let tokens = Arc::new(tokens);
        imap_mail::check_login(&servers, Credential::Microsoft(tokens.clone())).map_err(named)?;
        let id = match existing {
            Some(id) => id,
            None => mail::new_account_id()?,
        };
        tokens.saved_as(&id)?;
        if self.account(&id)?.is_some() {
            locked(&self.open).remove(&id);
            return self
                .accounts()
                .into_iter()
                .find(|a| a.id == id)
                .ok_or_else(|| NimbraError::invalid("That account was removed meanwhile."));
        }
        self.keep_account(AccountRef {
            id,
            email,
            servers: Some(servers),
            oauth: Some(microsoft::PROVIDER.to_string()),
        })
    }

    /// Forgets a sign-in that was started and will not be finished (the user closed the
    /// browser). Memory only.
    pub fn cancel_sign_in(&self, request_id: String) {
        locked(&self.pending).remove(&request_id);
    }

    /// Finds an address's servers: the well-known providers, then autoconfig and MX
    /// records. Network.
    pub fn discover_servers(&self, email: String) -> Result<Discovery> {
        Ok(discover::discover(&email)?.into())
    }

    /// Adds an account with its own servers (found with `discover_servers`, or typed in),
    /// after checking that both servers take the password. Network.
    pub fn add_imap_account(
        &self,
        email: String,
        servers: MailServers,
        password: String,
    ) -> Result<Account> {
        let email = email.trim().to_string();
        if !mail::is_address(&email) {
            return Err(NimbraError::invalid("That is not an email address."));
        }
        if self.has_email(&email) {
            return Err(already_here(&email));
        }
        let servers = servers::Servers::from(&servers);
        let password = servers.normalize_password(&password);
        if password.is_empty() {
            return Err(NimbraError::invalid("The password is empty."));
        }
        servers
            .check()
            .map_err(|e| NimbraError::invalid(e.to_string()))?;
        accounts::check_password(&servers, &password)?;
        let id = mail::new_account_id()?;
        servers::store_password(&id, &password)?;
        self.keep_account(AccountRef {
            id,
            email,
            servers: Some(servers),
            oauth: None,
        })
    }

    /// Signs in to an account with its own servers again, with a new password (it was
    /// changed, or the server stopped taking the old one: `SignedOut`). Checks that both
    /// servers take it, as `add_imap_account` does, then keeps it in the Keychain in place
    /// of the old one; the account keeps its id, its stored mail, its signatures and
    /// whatever waits to be sent. A refused password is `SignedOut` for this account, and
    /// the old one is kept. Not for Gmail or Microsoft accounts, which sign in again in
    /// the browser. Network.
    pub fn update_imap_password(&self, account_id: String, password: String) -> Result<Account> {
        let account = self
            .account(&account_id)?
            .ok_or_else(|| NimbraError::invalid("There is no such account."))?;
        let servers = match (&account.servers, kind_of(&account)) {
            (Some(servers), AccountKind::Imap) => servers.clone(),
            _ => {
                return Err(NimbraError::invalid(
                    "That account signs in with its provider, not a password.",
                ));
            }
        };
        let password = servers.normalize_password(&password);
        if password.is_empty() {
            return Err(NimbraError::invalid("The password is empty."));
        }
        accounts::check_password(&servers, &password)
            .map_err(|e| NimbraError::from(e).for_account(&account_id))?;
        servers::store_password(&account_id, &password)?;
        // The connection opens again with it; the store stays as it is.
        locked(&self.open).remove(&account_id);
        self.accounts()
            .into_iter()
            .find(|a| a.id == account_id)
            .ok_or_else(|| NimbraError::invalid("That account was removed meanwhile."))
    }

    /// Removes an account from this device: its sign-in, its stored mail and its
    /// signatures. Nothing on the server changes. Disk and Keychain.
    pub fn remove_account(&self, account_id: String) -> Result<()> {
        if self.account(&account_id)?.is_none() {
            return Err(NimbraError::invalid("There is no such account."));
        }
        locked(&self.open).remove(&account_id);
        // As signing out on the Mac: whoever signs in next must not send its mail.
        for job in locked(&self.waiting)
            .remove(&account_id)
            .unwrap_or_default()
        {
            job.forget();
        }
        accounts::forget_secrets_and_mail(&account_id);
        self.change_settings(|settings| {
            accounts::remove(settings, &account_id);
            Ok(())
        })
    }

    // -------------------------------------------------------------- mailboxes

    /// The account's own labels (IMAP: its folders). Network.
    pub fn labels(&self, account_id: String) -> Result<Vec<Label>> {
        let open = self.connect(&account_id)?;
        let mut labels = open.client.labels()?;
        listing::sort_labels(&mut labels);
        Self::keep_labels(&open, |kept| *kept = labels.clone())?;
        Ok(labels.into_iter().map(Label::from).collect())
    }

    /// Unread and total threads for these labels ("INBOX", "STARRED", label ids). Network.
    ///
    /// For a Gmail account, Gmail counts each label over all mail, as the Mac shows it:
    /// a Split Inbox category (`CATEGORY_PERSONAL`, `CATEGORY_UPDATES`,
    /// `CATEGORY_PROMOTIONS`, `CATEGORY_SOCIAL`) counts its threads archived out of the
    /// inbox too, so a category's unread number can be more than its list in the inbox
    /// shows. "INBOX" counts only the inbox.
    pub fn counts(&self, account_id: String, label_ids: Vec<String>) -> Result<Vec<LabelCount>> {
        let open = self.connect(&account_id)?;
        let counts = open.client.counts(&label_ids);
        Ok(label_ids
            .into_iter()
            .filter_map(|id| {
                let (unread, total) = *counts.get(&id)?;
                Some(LabelCount {
                    label_id: id,
                    unread,
                    total,
                })
            })
            .collect())
    }

    /// Searches the account's mail (Gmail's search words, or text for IMAP). Network.
    pub fn search(
        &self,
        account_id: String,
        query: String,
        page: Option<String>,
        limit: u32,
    ) -> Result<ThreadPage> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(ThreadPage {
                threads: Vec::new(),
                next_page: None,
            });
        }
        let open = self.connect(&account_id)?;
        let limit = limit.clamp(1, 100) as usize;
        let (threads, next_page) =
            open.client
                .threads_page(mail::View::Search, Some(query), limit, page.as_deref())?;
        Ok(ThreadPage {
            threads: threads.iter().map(ThreadRow::from).collect(),
            next_page,
        })
    }

    /// One thread's row, fresh. Network.
    pub fn thread_summary(&self, account_id: String, thread_id: String) -> Result<ThreadRow> {
        let open = self.connect(&account_id)?;
        Ok((&open.client.summary(&thread_id, false)?).into())
    }

    /// What changed since `cursor` (`None`: start from now), and what to notify about, as
    /// the Mac decides: blocked senders' new mail is put away first and never notifies, the
    /// first few new threads are named and the rest counted. On the first look (no cursor)
    /// what blocked senders left in the inbox meanwhile is put away. Network.
    pub fn check_for_changes(
        &self,
        account_id: String,
        cursor: Option<String>,
    ) -> Result<SyncResult> {
        let open = self.connect(&account_id)?;
        let notify = self.preferences().notifications;
        let fresh = |expired: bool| -> Result<SyncResult> {
            let (_, latest) = open.client.profile()?;
            Ok(SyncResult {
                cursor: latest,
                changed_threads: Vec::new(),
                new_unread_inbox: Vec::new(),
                named: Vec::new(),
                more_new: 0,
                notify,
                expired,
            })
        };
        let Some(cursor) = cursor.filter(|c| !c.is_empty()) else {
            blocking::sweep(&*open.client, &open.store);
            return fresh(false);
        };
        match open.client.history(&cursor) {
            Ok(changes) => {
                let news = nimbra_core::notifying::new_mail(
                    &*open.client,
                    Some(&open.store),
                    changes.new_unread_inbox,
                );
                Ok(SyncResult {
                    cursor: changes.latest,
                    changed_threads: changes.threads,
                    new_unread_inbox: news.fresh,
                    named: news.named.iter().map(ThreadRow::from).collect(),
                    more_new: news.more as u32,
                    notify,
                    expired: false,
                })
            }
            Err(error) if error.is::<mail::HistoryExpired>() => fresh(true),
            Err(error) => Err(error.into()),
        }
    }

    /// The app icon's number: unread threads in every account's inbox, as last counted
    /// (each account once), or 0 when the badge is off in Preferences. Disk.
    pub fn badge_count(&self) -> Result<u32> {
        if !self.preferences().badge {
            return Ok(0);
        }
        let mut unread = HashMap::new();
        for account in self.accounts() {
            // One that cannot be opened (signed out, or removed meanwhile) does not count.
            let Ok(open) = self.connect(&account.id) else {
                continue;
            };
            let meta: listing::Meta = open.store.load(listing::META).unwrap_or_default();
            let count = meta.counts.get("INBOX").map_or(0, |(unread, _)| *unread);
            unread.insert(account.id, count);
        }
        Ok(nimbra_core::notifying::inbox_badge(
            "",
            unread.get("").copied(),
            &unread,
            |_| true,
        ))
    }

    /// When an opened thread counts as read (Preferences): at once (0), after a moment, or
    /// only when the user says so (`None`). Memory only.
    pub fn mark_read_after_ms(&self) -> Option<u32> {
        let choice = locked(&self.settings).mark_read;
        nimbra_core::notifying::mark_read_after(choice).map(|after| after.as_millis() as u32)
    }

    // -------------------------------------------------------------- reading

    /// An attachment's content. Network.
    pub fn download_attachment(
        &self,
        account_id: String,
        message_id: String,
        attachment_id: String,
    ) -> Result<Vec<u8>> {
        let open = self.connect(&account_id)?;
        Ok(open.client.download(&message_id, &attachment_id)?)
    }

    // -------------------------------------------------------------- actions

    /// Done, star, read and the like. Offline, it waits in the account's queue and is made
    /// once the server can be reached (`catch_up`), as on the Mac. Network.
    pub fn apply(
        &self,
        account_id: String,
        thread_id: String,
        action: ThreadAction,
    ) -> Result<ActionOutcome> {
        let open = self.connect(&account_id)?;
        match open.client.change(&thread_id, action.change()) {
            Ok(()) => Ok(ActionOutcome::Done),
            Err(error) if error.is::<mail::Offline>() => {
                nimbra_core::outbox::queue(&open.store, &thread_id, action.change())?;
                Ok(ActionOutcome::Queued)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Adds and removes labels in one change (a move: add the label, remove "INBOX").
    /// Network.
    pub fn relabel(
        &self,
        account_id: String,
        thread_id: String,
        add: Vec<String>,
        remove: Vec<String>,
    ) -> Result<()> {
        let open = self.connect(&account_id)?;
        let add: Vec<&str> = add.iter().map(String::as_str).collect();
        let remove: Vec<&str> = remove.iter().map(String::as_str).collect();
        open.client.relabel(&thread_id, &add, &remove)?;
        Ok(())
    }

    /// A new label, unless one is already called that (in any case): then that one, as on
    /// the Mac. Network (disk when it exists).
    pub fn create_label(&self, account_id: String, name: String) -> Result<Label> {
        let name = name.trim();
        if name.is_empty() {
            return Err(NimbraError::invalid("A label needs a name."));
        }
        let open = self.connect(&account_id)?;
        let meta: listing::Meta = open.store.load(listing::META).unwrap_or_default();
        if let Some(existing) = listing::label_named(&meta.labels, name) {
            return Ok(existing.clone().into());
        }
        let label = open.client.create_label(name)?;
        let made = label.clone();
        Self::keep_labels(&open, move |kept| kept.push(made))?;
        Ok(label.into())
    }

    /// Network.
    pub fn rename_label(&self, account_id: String, label_id: String, name: String) -> Result<()> {
        let name = name.trim().to_string();
        let open = self.connect(&account_id)?;
        open.client.rename_label(&label_id, &name)?;
        Self::keep_labels(&open, |kept| {
            for label in kept.iter_mut().filter(|l| l.id == label_id) {
                label.name = name.clone();
            }
        })
    }

    /// Deletes a label; the mail stays. Network.
    pub fn delete_label(&self, account_id: String, label_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        open.client.delete_label(&label_id)?;
        Self::keep_labels(&open, |kept| kept.retain(|l| l.id != label_id))
    }

    /// Deletes a thread for good (Gmail may need `NeedsFullAccess` first). Network.
    pub fn delete_thread(&self, account_id: String, thread_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        open.client.delete_thread(&thread_id)?;
        Ok(())
    }

    /// Puts a thread away until `until_ms`, kept with its account as the macOS app keeps it:
    /// out of the inbox now, back unread when the time comes (`wake_due`).
    /// `only_if_no_reply` makes it a reminder. Network (disk when it is already out).
    pub fn snooze(
        &self,
        account_id: String,
        thread_id: String,
        until_ms: i64,
        only_if_no_reply: bool,
    ) -> Result<()> {
        let open = self.connect(&account_id)?;
        let row = match listing::find_kept(&open.store, &thread_id) {
            Some(row) => row,
            None => listing::Row::from_summary(open.client.summary(&thread_id, false)?),
        };
        let item = snooze::Snooze::new(&row, until_ms, only_if_no_reply);
        open.store
            .update(snooze::LIST, |list: &mut Vec<snooze::Snooze>| {
                snooze::put(list, std::slice::from_ref(&item))
            })?;
        if row.labels.iter().any(|label| label == "INBOX") {
            open.client.change(&thread_id, mail::Change::Archive)?;
        }
        Ok(())
    }

    /// Snoozed threads and reminders, soonest first. Disk.
    pub fn snoozed(&self, account_id: String) -> Result<Vec<SnoozedThread>> {
        let open = self.connect(&account_id)?;
        let mut list = snooze::list(&open.store);
        list.sort_by_key(|item| item.until_ms);
        Ok(list.iter().map(SnoozedThread::from).collect())
    }

    /// Cancels a snooze (Undo): out of the list, and the thread back in the inbox. Network.
    pub fn unsnooze(&self, account_id: String, thread_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        let mut had = false;
        open.store
            .update(snooze::LIST, |list: &mut Vec<snooze::Snooze>| {
                had = list.iter().any(|s| s.thread_id == thread_id);
                snooze::forget(list, std::slice::from_ref(&thread_id));
            })?;
        if had {
            open.client.change(&thread_id, mail::Change::Unarchive)?;
        }
        Ok(())
    }

    /// Brings back the snoozes due by now, each through its own account. The ones that came
    /// back (to notify about: "Back from snooze", or for a reminder "No reply yet"). One
    /// that could not be checked (offline) stays for next time. Network.
    pub fn wake_due(&self, account_id: String) -> Result<Vec<SnoozedThread>> {
        let open = self.connect(&account_id)?;
        let mut back = Vec::new();
        for item in snooze::due(&snooze::list(&open.store), now_ms()) {
            let owner = item
                .mail
                .account
                .clone()
                .unwrap_or_else(|| account_id.clone());
            let Ok(theirs) = self.connect(&owner) else {
                continue;
            };
            if matches!(
                snooze::wake_kept(&open.store, &*theirs.client, &item),
                Ok(true)
            ) {
                back.push(SnoozedThread::from(&item));
            }
        }
        Ok(back)
    }

    /// Blocks a sender, as the Mac does: on the account's list from now on, their threads
    /// in the inbox put away in the Blocked label (made when there is none), and
    /// `thread_id` (theirs, open in `from`) moved there as Move to does. Their mail never
    /// notifies. Network.
    pub fn block_sender(
        &self,
        account_id: String,
        address: String,
        thread_id: Option<String>,
        from: Mailbox,
    ) -> Result<()> {
        let address = mail::address_of(&address).to_lowercase();
        if !mail::is_address(&address) {
            return Err(NimbraError::invalid("That is not an email address."));
        }
        let open = self.connect(&account_id)?;
        let (label, _) = blocking::block(&*open.client, &open.store, &address)?;
        if let Some(thread_id) = thread_id {
            self.move_to_label(account_id, thread_id, label, from)?;
        }
        Ok(())
    }

    /// Unblocks a sender: off the list, and `thread_id` (theirs) out of the Blocked label
    /// and back in the inbox. Network (disk without a thread).
    pub fn unblock_sender(
        &self,
        account_id: String,
        address: String,
        thread_id: Option<String>,
    ) -> Result<()> {
        let open = self.connect(&account_id)?;
        blocking::set(&open.store, &mail::address_of(&address), false)?;
        if let Some(thread_id) = thread_id {
            let label = blocking::label_id(&*open.client)?;
            open.client
                .relabel(&thread_id, &["INBOX"], &[label.as_str()])?;
        }
        Ok(())
    }

    /// Move to Inbox from `from`: out of Spam (not spam) or Trash (restored), else out of
    /// the archive. Offline, it waits as `apply` does. Network.
    pub fn move_to_inbox(
        &self,
        account_id: String,
        thread_id: String,
        from: Mailbox,
    ) -> Result<ActionOutcome> {
        let (view, _) = from.view();
        let change = listing::to_inbox(view);
        self.apply(account_id, thread_id, ThreadAction::from_change(change))
    }

    /// Move to a label from `from`: the label added and, from an inbox (one account's, All
    /// inboxes or a Split Inbox category), out of the inbox: a move, not a copy, as on the
    /// Mac. Network.
    pub fn move_to_label(
        &self,
        account_id: String,
        thread_id: String,
        label_id: String,
        from: Mailbox,
    ) -> Result<()> {
        let open = self.connect(&account_id)?;
        let (view, _) = from.view();
        let leaves: &[&str] = if listing::inbox_like(view) {
            &["INBOX"]
        } else {
            &[]
        };
        open.client
            .relabel(&thread_id, &[label_id.as_str()], leaves)?;
        Ok(())
    }

    /// Disk.
    pub fn blocked_senders(&self, account_id: String) -> Result<Vec<String>> {
        let open = self.connect(&account_id)?;
        Ok(blocking::load(&open.store).senders)
    }

    // -------------------------------------------------------------- drafts and sending

    /// The draft in a thread (Drafts lists threads). Network.
    pub fn draft_for_thread(&self, account_id: String, thread_id: String) -> Result<DraftMessage> {
        let open = self.connect(&account_id)?;
        Ok(open.client.draft_for_thread(&thread_id)?.into())
    }

    /// Saves a draft, new or over `draft_id`. Its id. Network.
    pub fn save_draft(
        &self,
        account_id: String,
        draft_id: Option<String>,
        message: OutgoingMessage,
    ) -> Result<String> {
        let open = self.connect(&account_id)?;
        Ok(open
            .client
            .save_draft(draft_id.as_deref(), &mail::Outgoing::from(&message))?)
    }

    /// Network.
    pub fn delete_draft(&self, account_id: String, draft_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        open.client.delete_draft(&draft_id)?;
        Ok(())
    }

    // -------------------------------------------------------------- contacts

    /// Address suggestions for what is typed, best first, as the Mac ranks them: what every
    /// account on the device learnt of the people it writes with, the account the message
    /// is written from (`account_id`) counting double. Never the user's own addresses, nor
    /// anyone already in the field (`present`). Disk.
    pub fn suggest_contacts(
        &self,
        account_id: String,
        query: String,
        present: Vec<String>,
    ) -> Result<Vec<Person>> {
        let accounts = self.accounts();
        let mine: Vec<String> = accounts.iter().map(|a| a.email.to_lowercase()).collect();
        let present: Vec<String> = present.iter().map(|a| a.trim().to_lowercase()).collect();
        let open: Vec<(String, Arc<Open>)> = accounts
            .into_iter()
            .filter_map(|a| Some((a.id.clone(), self.connect(&a.id).ok()?)))
            .collect();
        let books = open
            .iter()
            .filter_map(|(id, open)| Some((id.as_str(), open.client.contacts()?.as_ref())));
        Ok(contacts::rank(
            query.trim(),
            &account_id,
            books,
            std::iter::empty(),
            &mine,
            &present,
        )
        .iter()
        .map(Person::from)
        .collect())
    }

    /// Pause `contact_scan_pause_seconds` before each step, as the Mac does, and stop when it
    /// says there is no more; what was learnt is kept, so the scan resumes where it was.
    /// Learns a little more about who the account writes with (one page of Sent or of the
    /// mail that came in). Whether there is more to learn. Network.
    pub fn learn_contacts(&self, account_id: String) -> Result<bool> {
        let open = self.connect(&account_id)?;
        match open.client.contacts() {
            Some(book) => Ok(book.scan_step(&*open.client)?),
            None => Ok(false),
        }
    }

    // -------------------------------------------------------------- signatures

    /// The account's signatures, and which one is its default. Memory only.
    pub fn signatures(&self, account_id: String) -> Vec<SignatureInfo> {
        let settings = locked(&self.settings);
        let default = settings
            .default_signature(&account_id)
            .map(|s| s.id.clone());
        settings
            .signatures_of(&account_id)
            .map(|s| SignatureInfo {
                id: s.id.clone(),
                account_id: s.account.clone(),
                name: s.name.clone(),
                html: s.html.clone(),
                is_default: default.as_deref() == Some(s.id.as_str()),
            })
            .collect()
    }

    /// A new, empty signature for the account. Its id. Disk.
    pub fn add_signature(&self, account_id: String) -> Result<String> {
        let mut made = None;
        self.change_settings(|settings| {
            made = settings.add_signature(&account_id);
            Ok(())
        })?;
        made.ok_or_else(|| NimbraError::invalid("A signature could not be added."))
    }

    /// Changes a signature. Its HTML is cleaned before it is kept (`signature::clean`).
    /// Disk.
    pub fn update_signature(&self, signature_id: String, name: String, html: String) -> Result<()> {
        let html = signature::clean(&html);
        self.change_settings(|settings| {
            let kept = settings
                .signatures
                .iter_mut()
                .find(|s| s.id == signature_id)
                .ok_or_else(|| NimbraError::invalid("There is no such signature."))?;
            kept.name = name.trim().to_string();
            kept.html = html;
            Ok(())
        })
    }

    /// Deletes a signature, and its place as any default. Disk.
    pub fn delete_signature(&self, signature_id: String) -> Result<()> {
        self.change_settings(|settings| {
            settings.delete_signature(&signature_id);
            Ok(())
        })
    }

    /// `None`: no signature by default. Disk.
    pub fn set_default_signature(
        &self,
        account_id: String,
        signature_id: Option<String>,
    ) -> Result<()> {
        self.change_settings(|settings| {
            settings.set_default_signature(&account_id, signature_id.as_deref());
            Ok(())
        })
    }

    // -------------------------------------------------------------- preferences

    /// The preferences, as set. Memory only.
    pub fn preferences(&self) -> Preferences {
        let settings = locked(&self.settings);
        Preferences {
            notifications: settings.notifications,
            original_view: settings.original_view,
            load_images: settings.load_images,
            dark_emails: settings.dark_emails,
            mark_read: settings.mark_read.into(),
            check_every_seconds: settings.check_every,
            undo_send_seconds: settings.undo_send,
            quote_replies: settings.quote_replies,
            badge: settings.dock_badge,
            notification_sound: settings.notify_sound,
        }
    }

    /// Changes the preferences and saves them. Disk.
    pub fn set_preferences(&self, preferences: Preferences) -> Result<()> {
        self.change_settings(|settings| {
            settings.notifications = preferences.notifications;
            settings.original_view = preferences.original_view;
            settings.load_images = preferences.load_images;
            settings.dark_emails = preferences.dark_emails;
            settings.mark_read = preferences.mark_read.into();
            settings.check_every = preferences.check_every_seconds.clamp(10, 24 * 60 * 60);
            settings.undo_send = preferences.undo_send_seconds.min(60);
            settings.quote_replies = preferences.quote_replies;
            settings.dock_badge = preferences.badge;
            settings.notify_sound = preferences.notification_sound;
            Ok(())
        })
    }
}

fn already_here(email: &str) -> NimbraError {
    NimbraError::invalid(format!("{email} is already here."))
}

pub(crate) fn kind_of(account: &AccountRef) -> AccountKind {
    match (&account.servers, account.oauth.as_deref()) {
        (None, _) => AccountKind::Gmail,
        (Some(_), Some(microsoft::PROVIDER)) => AccountKind::Microsoft,
        (Some(_), _) => AccountKind::Imap,
    }
}

impl Engine {
    fn google(&self) -> Result<&gmail::Config> {
        self.google
            .as_ref()
            .ok_or_else(|| NimbraError::invalid("Google sign-in is not set up in this app."))
    }

    fn microsoft(&self) -> Result<&microsoft::Config> {
        self.microsoft
            .as_ref()
            .ok_or_else(|| NimbraError::invalid("Microsoft sign-in is not set up in this app."))
    }

    pub(crate) fn account(&self, id: &str) -> Result<Option<AccountRef>> {
        Ok(locked(&self.settings)
            .accounts
            .iter()
            .find(|a| a.id == id)
            .cloned())
    }

    fn has_email(&self, email: &str) -> bool {
        // Not `accounts::duplicate_of`: it skips an id, and the first account's is "".
        locked(&self.settings)
            .accounts
            .iter()
            .any(|a| a.email.eq_ignore_ascii_case(email))
    }

    /// Changes the account's kept labels (sorted, as they are listed) as the server has
    /// them now. Disk.
    fn keep_labels(open: &Open, change: impl FnOnce(&mut Vec<mail::Label>)) -> Result<()> {
        open.store
            .update(listing::META, |meta: &mut listing::Meta| {
                change(&mut meta.labels);
                listing::sort_labels(&mut meta.labels);
            })?;
        Ok(())
    }

    /// Changes the settings and saves them, unless `change` refuses.
    fn change_settings(&self, change: impl FnOnce(&mut Settings) -> Result<()>) -> Result<()> {
        let mut settings = locked(&self.settings);
        change(&mut settings)?;
        settings::save(&settings)?;
        Ok(())
    }

    /// Keeps a new account, unless its address is here already (two adds of the same
    /// address can both pass `has_email` while their servers are asked): then the sign-in
    /// just saved for it is forgotten.
    fn keep_account(&self, account: AccountRef) -> Result<Account> {
        let id = account.id.clone();
        let mut duplicate = false;
        self.change_settings(|settings| {
            duplicate = settings
                .accounts
                .iter()
                .any(|a| a.email.eq_ignore_ascii_case(&account.email));
            if duplicate {
                return Err(already_here(&account.email));
            }
            settings.accounts.push(account);
            Ok(())
        })
        .inspect_err(|_| {
            if duplicate {
                accounts::forget_secrets_and_mail(&id);
            }
        })?;
        self.accounts()
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| NimbraError::invalid("The account could not be kept."))
    }

    fn pend(&self, url: String, pending: Pending) -> Result<SignInRequest> {
        let id = mail::random_hex(16)?;
        let mut all = locked(&self.pending);
        // Only the newest few are kept: a browser that never came back is forgotten.
        if all.len() >= 8 {
            all.clear();
        }
        all.insert(id.clone(), pending);
        Ok(SignInRequest { id, url })
    }

    fn take_pending(&self, id: &str, google: bool) -> Option<Pending> {
        let mut all = locked(&self.pending);
        let is_google = matches!(all.get(id)?, Pending::Google { .. });
        if is_google != google {
            return None;
        }
        all.remove(id)
    }

    /// The account's connection and store, opened on first use with its sign-in from the
    /// Keychain.
    pub(crate) fn connect(&self, account_id: &str) -> Result<Arc<Open>> {
        if let Some(open) = locked(&self.open).get(account_id) {
            return Ok(open.clone());
        }
        let account = self
            .account(account_id)?
            .ok_or_else(|| NimbraError::invalid("There is no such account."))?;
        let signed_out = || NimbraError::SignedOut {
            account_id: Some(account.id.clone()),
        };
        // As the Mac connects: the sign-in or password from the Keychain (`accounts`).
        let client: Arc<mail::Client> = match kind_of(&account) {
            AccountKind::Gmail => {
                let token = gmail::stored_refresh_token(&account.id)?.ok_or_else(signed_out)?;
                accounts::gmail_connection(self.google()?.clone(), token, &account)
            }
            _ => {
                let microsoft = if accounts::is_microsoft(&account) {
                    Some(self.microsoft()?)
                } else {
                    None
                };
                let credential =
                    accounts::stored_credential(&account.id, microsoft)?.ok_or_else(signed_out)?;
                accounts::imap_connection(&account, Some(credential)).ok_or_else(signed_out)?
            }
        };
        let store = Arc::new(Store::open(&account.id)?);
        client.keep_rows_in(&store);
        // Another thread may have opened it meanwhile: theirs is kept.
        let open = Arc::new(Open { client, store });
        Ok(locked(&self.open).entry(account.id).or_insert(open).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One engine per test process, in a fresh temporary folder: the folders are set once per
    /// process, and no test may touch the Mac app's own files or Keychain.
    fn engine() -> Arc<Engine> {
        static ENGINE: std::sync::OnceLock<Arc<Engine>> = std::sync::OnceLock::new();
        ENGINE
            .get_or_init(|| {
                let dir = std::env::temp_dir()
                    .join(format!("nimbra-ffi-test-{}", mail::random_hex(8).unwrap()));
                let memory: Arc<dyn SecretStore> = crate::secrets::tests::memory();
                Engine::new(
                    EngineConfig {
                        google_client_id: Some("test.apps.googleusercontent.com".into()),
                        google_client_secret: None,
                        microsoft_client_id: None,
                    },
                    dir.join("data").to_string_lossy().into_owned(),
                    dir.join("cache").to_string_lossy().into_owned(),
                    Some(memory),
                )
                .unwrap()
            })
            .clone()
    }

    #[test]
    fn the_engine_keeps_preferences_in_its_own_folder() {
        // The engine is shared: other tests' accounts come and go meanwhile.
        let engine = engine();
        let mut preferences = engine.preferences();
        preferences.undo_send_seconds = 10;
        preferences.load_images = !preferences.load_images;
        engine.set_preferences(preferences.clone()).unwrap();
        assert_eq!(engine.preferences(), preferences);
        assert!(engine.flush());
        let saved = paths::data_dir().unwrap().join("settings.json");
        assert!(saved.exists(), "{saved:?}");
    }

    #[test]
    fn the_folders_are_required_and_set_once() {
        let _ = engine();
        let config = || EngineConfig {
            google_client_id: None,
            google_client_secret: None,
            microsoft_client_id: None,
        };
        assert!(Engine::new(config(), String::new(), "/tmp".into(), None).is_err());
        assert!(Engine::new(config(), "/elsewhere".into(), "/elsewhere/c".into(), None).is_err());
    }

    #[test]
    fn a_google_sign_in_points_at_google_with_pkce_and_no_secret() {
        let engine = engine();
        let request = engine
            .begin_google_sign_in(
                "com.googleusercontent.apps.test:/oauth2redirect".into(),
                None,
                false,
            )
            .unwrap();
        let url = url_of(&request.url);
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        assert_eq!(param("code_challenge_method").as_deref(), Some("S256"));
        assert!(param("state").is_some_and(|state| state.len() >= 32));
        assert!(param("client_secret").is_none());
        // A callback with another state is refused, and the sign-in is then over.
        let wrong = "com.googleusercontent.apps.test:/oauth2redirect?state=nope&code=c";
        assert!(
            engine
                .finish_google_sign_in(request.id.clone(), wrong.into())
                .is_err()
        );
        assert!(
            engine
                .finish_google_sign_in(request.id, wrong.into())
                .is_err()
        );
    }

    #[test]
    fn unknown_accounts_are_refused_without_the_network() {
        let engine = engine();
        assert!(matches!(
            engine.refresh_mailbox("nobody".into(), Mailbox::Inbox),
            Err(NimbraError::Invalid { .. })
        ));
        assert!(engine.remove_account("nobody".into()).is_err());
        assert!(
            engine
                .begin_microsoft_sign_in("msauth.x://auth".into(), None, None)
                .is_err()
        );
    }

    /// An account on the test engine whose connection is a fake server, and that server.
    pub(crate) fn fake_account(
        engine: &Engine,
        email: &str,
    ) -> (String, Arc<nimbra_core::testing::Fake>) {
        let fake = nimbra_core::testing::Fake::new(email);
        let id = mail::new_account_id().unwrap();
        engine
            .change_settings(|settings| {
                settings.accounts.push(AccountRef {
                    id: id.clone(),
                    email: email.to_string(),
                    servers: None,
                    oauth: None,
                });
                Ok(())
            })
            .unwrap();
        let client: Arc<mail::Client> = fake.clone();
        locked(&engine.open).insert(
            id.clone(),
            Arc::new(Open {
                client,
                store: Arc::new(Store::temp()),
            }),
        );
        (id, fake)
    }

    #[test]
    fn a_mailbox_is_kept_and_opens_from_the_device() {
        let engine = engine();
        let (id, fake) = fake_account(&engine, "lists@example.com");
        fake.add(nimbra_core::testing::Fake::thread(
            "a",
            &["INBOX", "UNREAD"],
            2,
        ));
        fake.add(nimbra_core::testing::Fake::thread("b", &["INBOX"], 1));
        assert!(
            engine
                .cached_threads(id.clone(), Mailbox::Inbox)
                .unwrap()
                .is_empty()
        );
        let page = engine.refresh_mailbox(id.clone(), Mailbox::Inbox).unwrap();
        let ids: Vec<_> = page.threads.iter().map(|t| t.id.clone()).collect();
        assert_eq!(ids, ["a", "b"]);
        assert_eq!(
            page.threads[0].sender_address.as_deref(),
            Some("a@example.com"),
            "the row knows its sender's address before the thread is read"
        );
        assert_eq!(
            engine.cached_threads(id.clone(), Mailbox::Inbox).unwrap(),
            page.threads
        );
        // Read once, then it opens offline.
        let thread = engine.read_thread(id.clone(), "a".into()).unwrap();
        fake.offline
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let kept = engine
            .cached_thread(id.clone(), "a".into())
            .unwrap()
            .unwrap();
        assert_eq!(kept.messages.last().unwrap().text, thread.messages[0].text);
        assert!(matches!(
            engine.refresh_mailbox(id.clone(), Mailbox::Inbox),
            Err(NimbraError::Offline)
        ));
        let entries = engine.mailboxes(id.clone()).unwrap();
        assert_eq!(entries[0].section, MailboxSection::Split);
        assert_eq!(
            entries[1].mailbox,
            Mailbox::Split {
                category: SplitCategory::Primary
            }
        );
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn every_accounts_trash_mixes_accounts_and_labels_have_none() {
        let engine = engine();
        let (first, one) = fake_account(&engine, "one@example.com");
        let (second, two) = fake_account(&engine, "two@example.com");
        one.add(nimbra_core::testing::Fake::thread("x", &["TRASH"], 1));
        two.add(nimbra_core::testing::Fake::thread("y", &["TRASH"], 5));
        two.add(nimbra_core::testing::Fake::thread("z", &["INBOX"], 9));
        let all = engine.every_mailbox(Mailbox::Trash, 0).unwrap();
        // Other tests' accounts may be listed too: only these two's threads are checked.
        let rows: Vec<_> = all
            .threads
            .iter()
            .filter(|t| ["x", "y", "z"].contains(&t.id.as_str()))
            .map(|t| (t.id.clone(), t.account_id.clone().unwrap()))
            .collect();
        assert_eq!(rows, [("y".into(), second), ("x".into(), first)]);
        assert!(matches!(
            engine.every_mailbox(Mailbox::Label { id: "L1".into() }, 0),
            Err(NimbraError::Invalid { .. })
        ));
    }

    #[test]
    fn all_inboxes_mixes_accounts_newest_first() {
        let engine = engine();
        let (first, one) = fake_account(&engine, "one@example.com");
        let (second, two) = fake_account(&engine, "two@example.com");
        one.add(nimbra_core::testing::Fake::thread("x", &["INBOX"], 1));
        two.add(nimbra_core::testing::Fake::thread(
            "y",
            &["INBOX", "UNREAD"],
            5,
        ));
        let all = engine.all_inboxes(0).unwrap();
        let rows: Vec<_> = all
            .threads
            .iter()
            .filter(|t| t.id == "x" || t.id == "y")
            .map(|t| (t.id.clone(), t.account_id.clone().unwrap()))
            .collect();
        assert_eq!(
            rows,
            [("y".into(), second.clone()), ("x".into(), first.clone())]
        );
        assert!(
            all.unread
                .iter()
                .any(|u| u.label_id == second && u.unread == 1)
        );
        engine.remove_account(first).unwrap();
        engine.remove_account(second).unwrap();
    }

    #[test]
    fn a_snooze_leaves_the_inbox_lists_under_snoozed_and_comes_back_unread() {
        use nimbra_core::testing::Fake;
        let engine = engine();
        let (id, fake) = fake_account(&engine, "snooze@example.com");
        fake.add(Fake::thread("s1", &["INBOX"], 5));
        fake.add(Fake::thread("s2", &["INBOX"], 4));
        engine.refresh_mailbox(id.clone(), Mailbox::Inbox).unwrap();
        engine.snooze(id.clone(), "s1".into(), 1, false).unwrap();
        engine
            .snooze(id.clone(), "s2".into(), i64::MAX, true)
            .unwrap();
        assert!(!fake.labels_of("s1").contains(&"INBOX".to_string()));
        let snoozed = engine
            .refresh_mailbox(id.clone(), Mailbox::Snoozed)
            .unwrap();
        assert_eq!(
            snoozed
                .threads
                .iter()
                .map(|t| t.id.as_str())
                .collect::<Vec<_>>(),
            ["s1"]
        );
        let reminders = engine
            .refresh_mailbox(id.clone(), Mailbox::Reminders)
            .unwrap();
        assert_eq!(reminders.threads[0].id, "s2");
        let back = engine.wake_due(id.clone()).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].thread_id, "s1");
        let labels = fake.labels_of("s1");
        assert!(labels.contains(&"INBOX".into()) && labels.contains(&"UNREAD".into()));
        assert_eq!(engine.snoozed(id.clone()).unwrap().len(), 1);
        engine.unsnooze(id.clone(), "s2".into()).unwrap();
        assert!(engine.snoozed(id.clone()).unwrap().is_empty());
        assert!(fake.labels_of("s2").contains(&"INBOX".to_string()));
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn a_message_waits_for_the_connection_and_a_change_made_offline_is_made_later() {
        use nimbra_core::testing::Fake;
        use std::sync::atomic::Ordering;
        let engine = engine();
        let (id, fake) = fake_account(&engine, "send@example.com");
        fake.add(Fake::thread("t", &["INBOX"], 1));
        let message = OutgoingMessage {
            to: "ana@example.com".into(),
            cc: String::new(),
            bcc: String::new(),
            subject: "Hello".into(),
            body: "Hi Ana".into(),
            html: None,
            files: Vec::new(),
            kept: Vec::new(),
            reply: None,
        };
        // Undo before it leaves: nothing goes.
        let undone = engine
            .queue_send(id.clone(), message.clone(), None)
            .unwrap();
        assert!(undone.deliver_at_ms() >= now_ms());
        assert!(undone.undo());
        assert_eq!(undone.deliver(), SendOutcome::NotWaiting);
        // Offline: it waits, and so does a Done.
        fake.offline.store(true, Ordering::SeqCst);
        let send = engine
            .queue_send(id.clone(), message.clone(), None)
            .unwrap();
        assert_eq!(send.deliver(), SendOutcome::WaitingForConnection);
        engine.wait_for_connection(send.clone());
        let outcome = engine
            .apply(id.clone(), "t".into(), ThreadAction::Done)
            .unwrap();
        assert_eq!(outcome, ActionOutcome::Queued);
        let pending = engine.pending_work(id.clone()).unwrap();
        assert_eq!((pending.queued_changes, pending.waiting_messages), (1, 1));
        assert!(pending.next_deadline_ms.is_some());
        assert!(matches!(
            engine.catch_up(id.clone()),
            Err(NimbraError::Offline)
        ));
        // Back online.
        fake.offline.store(false, Ordering::SeqCst);
        let done = engine.catch_up(id.clone()).unwrap();
        assert_eq!((done.changes, done.sent), (1, 1));
        assert!(done.done);
        assert!(!fake.labels_of("t").contains(&"INBOX".to_string()));
        assert_eq!(fake.sent.lock().unwrap().len(), 1, "sent once, not twice");
        assert_eq!(
            engine.pending_work(id.clone()).unwrap().next_deadline_ms,
            None
        );
        // Send later, due at once.
        let later = engine
            .schedule_send(id.clone(), message.clone(), None, 1)
            .unwrap();
        assert_eq!(
            engine.scheduled_sends(id.clone()).unwrap()[0].draft_id,
            later.draft_id
        );
        assert_eq!(engine.send_due(id.clone()).unwrap(), [later.draft_id]);
        assert_eq!(fake.sent.lock().unwrap().len(), 2);
        // Nothing to send is refused before it is kept.
        let empty = OutgoingMessage {
            subject: String::new(),
            body: String::new(),
            ..message
        };
        assert!(matches!(
            engine.queue_send(id.clone(), empty, None),
            Err(NimbraError::Invalid { .. })
        ));
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn a_reply_answers_the_latest_message_once_and_quotes_it() {
        let engine = engine();
        let (id, fake) = fake_account(&engine, "answer@example.com");
        fake.add(nimbra_core::testing::Fake::thread("r", &["INBOX"], 5));
        let start = engine
            .start_answer(id.clone(), "r".into(), AnswerKind::ReplyAll, "Tue".into())
            .unwrap();
        assert_eq!(start.subject, "Re: Subject r");
        assert_eq!(start.to, ["r@example.com"], "never to the account itself");
        assert_eq!(
            start.reply.as_ref().map(|r| r.thread_id.as_str()),
            Some("r")
        );
        let forward = engine
            .start_answer(id.clone(), "r".into(), AnswerKind::Forward, String::new())
            .unwrap();
        assert!(
            forward
                .quoted
                .unwrap()
                .starts_with("---------- Forwarded message")
        );
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn labels_are_made_once_by_name_and_listed_as_they_change() {
        let engine = engine();
        let (id, _fake) = fake_account(&engine, "labels@example.com");
        let made = engine.create_label(id.clone(), "Travel".into()).unwrap();
        let again = engine.create_label(id.clone(), " travel ".into()).unwrap();
        assert_eq!(made, again, "a label by that name is that label");
        engine.create_label(id.clone(), "Bills".into()).unwrap();
        let names = |engine: &Engine| -> Vec<String> {
            engine
                .mailboxes(id.clone())
                .unwrap()
                .into_iter()
                .filter_map(|entry| entry.name)
                .collect()
        };
        assert_eq!(names(&engine), ["Bills", "Travel"]);
        engine
            .rename_label(id.clone(), made.id.clone(), "Trips".into())
            .unwrap();
        engine.delete_label(id.clone(), made.id.clone()).unwrap();
        assert_eq!(names(&engine), ["Bills"]);
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn a_watch_wakes_on_a_change_and_stops_when_cancelled() {
        let engine = engine();
        let (id, fake) = fake_account(&engine, "watch@example.com");
        let watch = engine.watch(id.clone()).unwrap();
        fake.changed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(watch.wait(5), WatchOutcome::Changed);
        watch.cancel();
        assert_eq!(watch.wait(60), WatchOutcome::Cancelled);
        assert!((10..=3600).contains(&engine.check_interval_seconds()));
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn a_watch_cancelled_before_it_waits_returns_at_once_every_time() {
        let engine = engine();
        let (id, fake) = fake_account(&engine, "early@example.com");
        let watch = engine.watch(id.clone()).unwrap();
        watch.cancel();
        // Even with a change to say: cancelled comes first.
        fake.changed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let began = std::time::Instant::now();
        assert_eq!(watch.wait(3600), WatchOutcome::Cancelled);
        assert_eq!(watch.wait(3600), WatchOutcome::Cancelled);
        assert!(began.elapsed() < std::time::Duration::from_millis(500));
        // A new watch waits again.
        assert_eq!(
            engine.watch(id.clone()).unwrap().wait(5),
            WatchOutcome::Changed
        );
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn a_password_is_updated_only_for_an_account_with_its_own_servers() {
        let engine = engine();
        let refused = |result: Result<Account>| match result {
            Err(NimbraError::Invalid { .. }) => {}
            other => panic!("expected Invalid, got {other:?}"),
        };
        refused(engine.update_imap_password("nobody".into(), "secret".into()));
        // A Gmail account signs in again in the browser.
        let (gmail, _fake) = fake_account(&engine, "pw-gmail@example.com");
        refused(engine.update_imap_password(gmail.clone(), "secret".into()));
        engine.remove_account(gmail).unwrap();
        let id = mail::new_account_id().unwrap();
        let servers = servers::Servers {
            username: "pw@example.com".into(),
            imap: servers::Server::new("imap.example.com", 993, servers::Security::Tls),
            smtp: servers::Server::new("smtp.example.com", 465, servers::Security::Tls),
        };
        engine
            .change_settings(|settings| {
                settings.accounts.push(AccountRef {
                    id: id.clone(),
                    email: "pw@example.com".into(),
                    servers: Some(servers),
                    oauth: None,
                });
                Ok(())
            })
            .unwrap();
        refused(engine.update_imap_password(id.clone(), String::new()));
        engine.remove_account(id).unwrap();
    }

    fn gmail_servers(email: &str) -> MailServers {
        (&servers::gmail(email)).into()
    }

    #[test]
    fn an_address_already_here_is_refused_before_any_server_is_asked() {
        let engine = engine();
        let (google, _fake) = fake_account(&engine, "twice@example.com");
        for typed in ["twice@example.com", " Twice@Example.COM "] {
            match engine.add_imap_account(
                typed.into(),
                gmail_servers("twice@example.com"),
                "abcd efgh ijkl mnop".into(),
            ) {
                Err(NimbraError::Invalid { message }) => {
                    assert!(message.contains("already here"), "{message}")
                }
                other => panic!("expected Invalid, got {other:?}"),
            }
        }
        engine.remove_account(google).unwrap();
    }

    #[test]
    fn the_same_address_is_kept_once_however_many_adds_finish() {
        let engine = engine();
        let account = |id: String| AccountRef {
            id,
            email: "race@example.com".into(),
            servers: Some(servers::gmail("race@example.com")),
            oauth: None,
        };
        let first = engine
            .keep_account(account(mail::new_account_id().unwrap()))
            .unwrap();
        let second = engine.keep_account(account(mail::new_account_id().unwrap()));
        assert!(
            matches!(second, Err(NimbraError::Invalid { .. })),
            "{second:?}"
        );
        let kept = engine
            .accounts()
            .into_iter()
            .filter(|a| a.email == "race@example.com")
            .count();
        assert_eq!(kept, 1);
        engine.remove_account(first.id).unwrap();
    }

    #[test]
    fn a_pasted_line_break_alone_is_an_empty_password() {
        let engine = engine();
        match engine.add_imap_account(
            "blank@gmail.com".into(),
            gmail_servers("blank@gmail.com"),
            " \n".into(),
        ) {
            Err(NimbraError::Invalid { message }) => {
                assert!(message.contains("empty"), "{message}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// Against the local test servers (docs/testing.md): `cargo test -p nimbra-ffi --
    /// --ignored live`, with NIMBRA_TEST_CA set.
    #[test]
    #[ignore]
    fn live_a_new_password_is_checked_with_both_servers_and_keeps_the_store() {
        let engine = engine();
        let user = format!("pw{}@example.org", std::process::id());
        let servers = MailServers {
            username: user.clone(),
            imap: MailServer {
                host: "localhost".into(),
                port: 10993,
                security: ServerSecurity::Tls,
            },
            smtp: MailServer {
                host: "localhost".into(),
                port: 10587,
                security: ServerSecurity::StartTls,
            },
        };
        let account = engine
            .add_imap_account(user.clone(), servers, "pass".into())
            .unwrap();
        let open = engine.connect(&account.id).unwrap();
        open.store.save("kept", &1u32).unwrap();
        // A refused password names the account and leaves the old one.
        assert!(matches!(
            engine.update_imap_password(account.id.clone(), "wrong".into()),
            Err(NimbraError::SignedOut { account_id: Some(id) }) if id == account.id
        ));
        assert_eq!(
            servers::stored_password(&account.id).unwrap().as_deref(),
            Some("pass")
        );
        let updated = engine
            .update_imap_password(account.id.clone(), "pass".into())
            .unwrap();
        assert_eq!(updated, account);
        let reopened = engine.connect(&account.id).unwrap();
        assert!(!Arc::ptr_eq(&open, &reopened), "the connection opens again");
        assert_eq!(
            reopened.store.load::<u32>("kept"),
            Some(1),
            "the store stays"
        );
        engine.remove_account(account.id).unwrap();
    }

    #[test]
    fn new_mail_from_a_blocked_sender_never_notifies_and_only_a_few_are_named() {
        use nimbra_core::testing::Fake;
        let engine = engine();
        let (id, fake) = fake_account(&engine, "notify@example.com");
        let first = engine.check_for_changes(id.clone(), None).unwrap();
        engine
            .block_sender(id.clone(), "n4@example.com".into(), None, Mailbox::Inbox)
            .unwrap();
        for i in 0..5 {
            fake.add(Fake::thread(&format!("n{i}"), &["INBOX", "UNREAD"], i));
        }
        *fake.changes.lock().unwrap() = nimbra_core::mail::Changes {
            latest: "9".into(),
            threads: (0..5).map(|i| format!("n{i}")).collect(),
            new_unread_inbox: (0..5).map(|i| format!("n{i}")).collect(),
        };
        let news = engine
            .check_for_changes(id.clone(), Some(first.cursor))
            .unwrap();
        assert_eq!(news.new_unread_inbox.len(), 4);
        assert_eq!((news.named.len(), news.more_new), (3, 1));
        assert!(!news.new_unread_inbox.contains(&"n4".to_string()));
        engine.refresh_mailbox(id.clone(), Mailbox::Inbox).unwrap();
        assert!(engine.badge_count().unwrap() >= 4);
        engine.remove_account(id).unwrap();
    }

    #[test]
    fn moves_and_blocks_follow_the_macs_rules() {
        use nimbra_core::testing::Fake;
        let engine = engine();
        let (id, fake) = fake_account(&engine, "moves@example.com");
        fake.add(Fake::thread("m1", &["INBOX", "STARRED"], 3));
        fake.add(Fake::thread("m2", &["INBOX", "STARRED"], 2));
        fake.add(Fake::thread("m3", &["TRASH"], 1));
        fake.add(Fake::thread("m4", &["INBOX"], 4));
        let label = engine.create_label(id.clone(), "Projects".into()).unwrap();
        engine
            .move_to_label(id.clone(), "m1".into(), label.id.clone(), Mailbox::Inbox)
            .unwrap();
        engine
            .move_to_label(id.clone(), "m2".into(), label.id.clone(), Mailbox::Starred)
            .unwrap();
        assert!(
            !fake.labels_of("m1").contains(&"INBOX".to_string()),
            "a move from the inbox"
        );
        assert!(
            fake.labels_of("m2").contains(&"INBOX".to_string()),
            "from Starred it stays"
        );
        engine
            .move_to_inbox(id.clone(), "m3".into(), Mailbox::Trash)
            .unwrap();
        assert!(!fake.labels_of("m3").contains(&"TRASH".to_string()));
        engine
            .block_sender(
                id.clone(),
                "m4@example.com".into(),
                Some("m4".into()),
                Mailbox::Inbox,
            )
            .unwrap();
        assert!(!fake.labels_of("m4").contains(&"INBOX".to_string()));
        assert_eq!(
            engine.blocked_senders(id.clone()).unwrap(),
            ["m4@example.com"]
        );
        engine
            .unblock_sender(id.clone(), "m4@example.com".into(), Some("m4".into()))
            .unwrap();
        assert!(fake.labels_of("m4").contains(&"INBOX".to_string()));
        assert!(engine.blocked_senders(id.clone()).unwrap().is_empty());
        engine.remove_account(id).unwrap();
    }

    fn url_of(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }
}
