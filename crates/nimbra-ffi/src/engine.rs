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
    blocking, contacts, discover, gmail, imap_mail, mail, microsoft, paths, scheduled, sending,
    servers, settings, signature, smtp, snooze, store,
};

use crate::error::{NimbraError, Result};
use crate::secrets::{self, SecretStore};
use crate::types::*;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// One account's connection and store.
struct Open {
    client: Arc<mail::Client>,
    store: Arc<Store>,
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
    sends: Mutex<u64>,
}

/// A message on its way: kept on the device from `queue_send` until the server has it.
#[derive(uniffi::Object)]
pub struct OutgoingSend {
    job: Arc<sending::Job>,
}

#[uniffi::export]
impl OutgoingSend {
    pub fn account_id(&self) -> String {
        self.job.account.clone()
    }

    pub fn subject(&self) -> String {
        self.job.subject()
    }

    pub fn stage(&self) -> SendStage {
        self.job.stage().into()
    }

    /// The message as it is now, to show again after Undo.
    pub fn message(&self) -> OutgoingMessage {
        let (_, outgoing) = self.job.mail();
        OutgoingMessage::from(outgoing.as_ref())
    }

    /// Whether it is kept on the device (so quitting cannot lose it).
    pub fn is_kept(&self) -> bool {
        self.job.kept()
    }

    /// Sends it, once however often this is called. `Ok(false)` when it was not waiting to
    /// be sent (sent already, taken back). Offline, it stays held to send again. Network.
    pub fn deliver(&self) -> Result<bool> {
        match self.job.send() {
            None => Ok(false),
            Some(Ok(())) => Ok(true),
            Some(Err(error)) => Err(error.into()),
        }
    }

    /// Undo send: takes it back while it has not left. Whether it was taken back.
    pub fn undo(&self) -> bool {
        if self.job.stage() != sending::Stage::Held {
            return false;
        }
        self.job.forget();
        true
    }

    /// Puts it in Drafts instead (a refused or unsure send). Its draft id, or `None` while
    /// that has not worked yet (it stays kept). Network.
    pub fn save_to_drafts(&self) -> Option<String> {
        self.job.saved_as_draft()
    }

    /// Deletes it and whatever draft was saved of it. Whether that worked. Network.
    pub fn discard(&self) -> bool {
        self.job.discard()
    }
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
        }))
    }

    /// Writes what is waiting to be written (settings, stores), for a few seconds at most:
    /// call it when the app goes to the background. Whether everything is on disk.
    pub fn flush(&self) -> bool {
        let settings = settings::flush();
        let stores = store::flush(std::time::Instant::now() + std::time::Duration::from_secs(3));
        settings && stores
    }

    // -------------------------------------------------------------- accounts

    /// The accounts on this device, in their order.
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
    /// for deleting for good.
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
        let client = authorization.finish(config, &account, &callback_url)?;
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
        if self.has_email(&email) {
            gmail::forget_refresh_token(&account);
            return Err(NimbraError::invalid(format!("{email} is already here.")));
        }
        self.keep_account(AccountRef {
            id: account,
            email,
            servers: None,
            oauth: None,
        })
    }

    /// Starts a Microsoft sign-in that comes back to `redirect_uri` (for iOS,
    /// `msauth.<bundle id>://auth`, as registered). `account_id` signs in to that account
    /// again. `hint` is an address to fill in.
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
        let (email, tokens) = authorization.finish(config, &callback_url)?;
        if let Some(id) = &existing {
            let expected = self
                .account(id)?
                .map(|a| a.email)
                .ok_or_else(|| NimbraError::invalid("That account was removed meanwhile."))?;
            microsoft::check_same_account(&expected, &email)?;
        } else if self.has_email(&email) {
            return Err(NimbraError::invalid(format!("{email} is already here.")));
        }
        let servers = microsoft::servers(&email);
        let tokens = Arc::new(tokens);
        imap_mail::check_login(&servers, Credential::Microsoft(tokens.clone()))?;
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
    /// browser).
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
            return Err(NimbraError::invalid(format!("{email} is already here.")));
        }
        if password.is_empty() {
            return Err(NimbraError::invalid("The password is empty."));
        }
        let servers = servers::Servers::from(&servers);
        servers
            .check()
            .map_err(|e| NimbraError::invalid(e.to_string()))?;
        imap_mail::check_login(&servers, Credential::Password(password.clone()))?;
        smtp::check_login(
            &servers.smtp,
            &servers.username,
            &servers::Secret::Password(password.clone()),
        )?;
        let id = mail::new_account_id()?;
        servers::store_password(&id, &password)?;
        self.keep_account(AccountRef {
            id,
            email,
            servers: Some(servers),
            oauth: None,
        })
    }

    /// Removes an account from this device: its sign-in, its stored mail and its
    /// signatures. Nothing on the server changes. Disk and Keychain.
    pub fn remove_account(&self, account_id: String) -> Result<()> {
        if self.account(&account_id)?.is_none() {
            return Err(NimbraError::invalid("There is no such account."));
        }
        locked(&self.open).remove(&account_id);
        gmail::forget_refresh_token(&account_id);
        servers::forget_password(&account_id);
        microsoft::forget_refresh_token(&account_id);
        store::wipe(&account_id);
        self.change_settings(|settings| {
            settings.accounts.retain(|a| a.id != account_id);
            settings.forget_signatures(&account_id);
            if settings.default_account.as_deref() == Some(account_id.as_str()) {
                settings.default_account = None;
            }
            Ok(())
        })
    }

    // -------------------------------------------------------------- mailboxes

    /// The account's own labels (IMAP: its folders). Network.
    pub fn labels(&self, account_id: String) -> Result<Vec<Label>> {
        let open = self.connect(&account_id)?;
        Ok(open
            .client
            .labels()?
            .into_iter()
            .map(|label| Label {
                id: label.id,
                name: label.name,
            })
            .collect())
    }

    /// Unread and total threads for these labels ("INBOX", "STARRED", label ids). Network.
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

    /// A page of a mailbox's threads, newest first. `page` is the last page's
    /// `next_page`. Network.
    pub fn list_threads(
        &self,
        account_id: String,
        mailbox: Mailbox,
        page: Option<String>,
        limit: u32,
    ) -> Result<ThreadPage> {
        let open = self.connect(&account_id)?;
        let (view, label) = mailbox.view();
        let limit = limit.clamp(1, 100) as usize;
        let (threads, next_page) = open
            .client
            .threads_page(view, label, limit, page.as_deref())?;
        Ok(ThreadPage {
            threads: threads.iter().map(ThreadSummary::from).collect(),
            next_page,
        })
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
            threads: threads.iter().map(ThreadSummary::from).collect(),
            next_page,
        })
    }

    /// One thread's row, fresh. Network.
    pub fn thread_summary(&self, account_id: String, thread_id: String) -> Result<ThreadSummary> {
        let open = self.connect(&account_id)?;
        Ok((&open.client.summary(&thread_id, false)?).into())
    }

    /// What changed since `cursor` (`None`: start from now). Mail from blocked senders that
    /// arrived is put away on the way. Network.
    pub fn check_for_changes(
        &self,
        account_id: String,
        cursor: Option<String>,
    ) -> Result<SyncResult> {
        let open = self.connect(&account_id)?;
        let fresh = |expired: bool| -> Result<SyncResult> {
            let (_, latest) = open.client.profile()?;
            Ok(SyncResult {
                cursor: latest,
                changed_threads: Vec::new(),
                new_unread_inbox: Vec::new(),
                expired,
            })
        };
        let Some(cursor) = cursor.filter(|c| !c.is_empty()) else {
            return fresh(false);
        };
        match open.client.history(&cursor) {
            Ok(changes) => {
                let new = blocking::screen(&*open.client, &open.store, changes.new_unread_inbox);
                Ok(SyncResult {
                    cursor: changes.latest,
                    changed_threads: changes.threads,
                    new_unread_inbox: new,
                    expired: false,
                })
            }
            Err(error) if error.is::<mail::HistoryExpired>() => fresh(true),
            Err(error) => Err(error.into()),
        }
    }

    // -------------------------------------------------------------- reading

    /// A thread's messages, parsed: text blocks, the original HTML, attachments. Network.
    pub fn read_thread(&self, account_id: String, thread_id: String) -> Result<MailThread> {
        let open = self.connect(&account_id)?;
        let messages = open.client.thread(&thread_id)?;
        Ok(MailThread {
            id: thread_id,
            messages: messages.iter().map(MailMessage::from).collect(),
        })
    }

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

    /// Done, star, read and the like. Network.
    pub fn apply(&self, account_id: String, thread_id: String, action: ThreadAction) -> Result<()> {
        let open = self.connect(&account_id)?;
        open.client.change(&thread_id, action.change())?;
        Ok(())
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

    /// Network.
    pub fn create_label(&self, account_id: String, name: String) -> Result<Label> {
        let open = self.connect(&account_id)?;
        let label = open.client.create_label(name.trim())?;
        Ok(Label {
            id: label.id,
            name: label.name,
        })
    }

    /// Network.
    pub fn rename_label(&self, account_id: String, label_id: String, name: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        open.client.rename_label(&label_id, name.trim())?;
        Ok(())
    }

    /// Network.
    pub fn delete_label(&self, account_id: String, label_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        open.client.delete_label(&label_id)?;
        Ok(())
    }

    /// Deletes a thread for good (Gmail may need `NeedsFullAccess` first). Network.
    pub fn delete_thread(&self, account_id: String, thread_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        open.client.delete_thread(&thread_id)?;
        Ok(())
    }

    /// Puts a thread away until `until_ms`: out of the inbox, and back unread when the time
    /// comes (`wake_due`). `only_if_no_reply` makes it a reminder. Network.
    pub fn snooze(
        &self,
        account_id: String,
        thread_id: String,
        until_ms: i64,
        only_if_no_reply: bool,
    ) -> Result<()> {
        let open = self.connect(&account_id)?;
        let row = open.client.summary(&thread_id, false)?;
        snooze::add(
            &open.store,
            snooze::Snoozed {
                thread_id: thread_id.clone(),
                until_ms,
                no_reply: only_if_no_reply,
                since_ms: row.timestamp_ms,
                subject: row.subject,
                sender: row.sender,
                snippet: row.snippet,
            },
        )?;
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

    /// Cancels a snooze and puts the thread back in the inbox. Network.
    pub fn unsnooze(&self, account_id: String, thread_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        if snooze::remove(&open.store, &thread_id)? {
            open.client.change(&thread_id, mail::Change::Unarchive)?;
        }
        Ok(())
    }

    /// Brings back what is due by now. The threads that came back. Network.
    pub fn wake_due(&self, account_id: String) -> Result<Vec<String>> {
        let open = self.connect(&account_id)?;
        Ok(snooze::wake_due(&open.store, &*open.client, now_ms()))
    }

    /// Blocks a sender: their mail goes to the Blocked label from now on, and `thread_id`
    /// (theirs) goes there now. Network.
    pub fn block_sender(
        &self,
        account_id: String,
        address: String,
        thread_id: Option<String>,
    ) -> Result<()> {
        let address = mail::address_of(&address).to_lowercase();
        if !mail::is_address(&address) {
            return Err(NimbraError::invalid("That is not an email address."));
        }
        let open = self.connect(&account_id)?;
        blocking::set(&open.store, &address, true)?;
        if let Some(thread_id) = thread_id {
            let label = blocking::label_id(&*open.client)?;
            blocking::put_away(&*open.client, &thread_id, &label)?;
        }
        Ok(())
    }

    /// Disk.
    pub fn unblock_sender(&self, account_id: String, address: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        blocking::set(
            &open.store,
            &mail::address_of(&address).to_lowercase(),
            false,
        )?;
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

    /// Send: keeps the message on the device and hands it back, held. Call `deliver` on it
    /// once the undo time (`Preferences.undo_send_seconds`) is over, or `undo` to take it
    /// back. `draft_id` is its saved draft, which sending uses up. Disk and Keychain.
    pub fn queue_send(
        &self,
        account_id: String,
        message: OutgoingMessage,
        draft_id: Option<String>,
    ) -> Result<Arc<OutgoingSend>> {
        let outgoing = mail::Outgoing::from(&message);
        outgoing
            .recipients()
            .map_err(|e| NimbraError::invalid(e.to_string()))?;
        if outgoing.attachment_size() > mail::ATTACHMENT_LIMIT {
            return Err(NimbraError::invalid("The attachments are over 25 MB."));
        }
        let open = self.connect(&account_id)?;
        let serial = {
            let mut sends = locked(&self.sends);
            *sends += 1;
            *sends
        };
        let job = sending::Job::new(
            account_id,
            serial,
            open.client.clone(),
            Some(open.store.clone()),
            sending::QueuedMail { draft_id, outgoing },
        )?;
        // Not kept: it can still be sent, but quitting before then loses it (`is_kept`).
        job.keep_asking();
        Ok(Arc::new(OutgoingSend { job }))
    }

    /// What an earlier run left unsent for this account: send each again (`deliver`), or,
    /// when it may have gone (`Unsure`) or was refused, put it in Drafts. Mail that was
    /// still being written goes to Drafts on its own. Disk.
    pub fn unsent(&self, account_id: String) -> Result<Vec<Arc<OutgoingSend>>> {
        let open = self.connect(&account_id)?;
        let mut left = Vec::new();
        for job in sending::Job::left_behind(&account_id, &open.client, &open.store) {
            match job.stage() {
                sending::Stage::Writing | sending::Stage::Unscheduled => {
                    job.to_drafts();
                }
                sending::Stage::Discarded => {
                    job.discard();
                }
                sending::Stage::Over => {}
                _ => left.push(Arc::new(OutgoingSend { job })),
            }
        }
        Ok(left)
    }

    /// Send later: saves the draft and keeps it on the list for `at_ms`. The app sends what
    /// is due with `send_due`. Network.
    pub fn schedule_send(
        &self,
        account_id: String,
        message: OutgoingMessage,
        draft_id: Option<String>,
        at_ms: i64,
    ) -> Result<ScheduledSend> {
        let outgoing = mail::Outgoing::from(&message);
        outgoing
            .recipients()
            .map_err(|e| NimbraError::invalid(e.to_string()))?;
        let open = self.connect(&account_id)?;
        let draft_id = open.client.save_draft(draft_id.as_deref(), &outgoing)?;
        let item = scheduled::Scheduled {
            draft_id,
            at_ms,
            subject: outgoing.subject.clone(),
            account: None,
        };
        scheduled::add(&open.store, item.clone())?;
        Ok((&item).into())
    }

    /// Disk.
    pub fn scheduled_sends(&self, account_id: String) -> Result<Vec<ScheduledSend>> {
        let open = self.connect(&account_id)?;
        let mut list = scheduled::list(&open.store);
        list.sort_by_key(|item| item.at_ms);
        Ok(list.iter().map(ScheduledSend::from).collect())
    }

    /// Takes a message off the send-later list. Its draft stays in Drafts. Disk.
    pub fn cancel_scheduled(&self, account_id: String, draft_id: String) -> Result<()> {
        let open = self.connect(&account_id)?;
        scheduled::remove(&open.store, &draft_id)?;
        Ok(())
    }

    /// Sends the send-later messages that are due. The drafts sent (or found gone).
    /// Network.
    pub fn send_due(&self, account_id: String) -> Result<Vec<String>> {
        let open = self.connect(&account_id)?;
        let now = now_ms();
        let due: Vec<String> = scheduled::list(&open.store)
            .into_iter()
            .filter(|item| item.at_ms <= now && item.account.is_none())
            .map(|item| item.draft_id)
            .collect();
        Ok(due
            .into_iter()
            .filter(|id| scheduled::send(&open.store, &*open.client, id).is_some())
            .collect())
    }

    // -------------------------------------------------------------- contacts

    /// Address suggestions for what is typed, best first, from the mail this account has
    /// seen. Disk.
    pub fn suggest_contacts(&self, account_id: String, query: String) -> Result<Vec<Person>> {
        let open = self.connect(&account_id)?;
        Ok(open
            .client
            .contacts()
            .map(|book| {
                book.suggest(query.trim())
                    .into_iter()
                    .take(contacts::SHOWN)
                    .map(|(person, _)| Person::from(&person))
                    .collect()
            })
            .unwrap_or_default())
    }

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

    /// A new, empty signature for the account. Its id.
    pub fn add_signature(&self, account_id: String) -> Result<String> {
        let mut made = None;
        self.change_settings(|settings| {
            made = settings.add_signature(&account_id);
            Ok(())
        })?;
        made.ok_or_else(|| NimbraError::invalid("A signature could not be added."))
    }

    /// Changes a signature. Its HTML is cleaned before it is kept (`signature::clean`).
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

    pub fn delete_signature(&self, signature_id: String) -> Result<()> {
        self.change_settings(|settings| {
            settings.delete_signature(&signature_id);
            Ok(())
        })
    }

    /// `None`: no signature by default.
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
        }
    }

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
            Ok(())
        })
    }
}

fn kind_of(account: &AccountRef) -> AccountKind {
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

    fn account(&self, id: &str) -> Result<Option<AccountRef>> {
        Ok(locked(&self.settings)
            .accounts
            .iter()
            .find(|a| a.id == id)
            .cloned())
    }

    fn has_email(&self, email: &str) -> bool {
        locked(&self.settings)
            .accounts
            .iter()
            .any(|a| a.email.eq_ignore_ascii_case(email))
    }

    /// Changes the settings and saves them, unless `change` refuses.
    fn change_settings(&self, change: impl FnOnce(&mut Settings) -> Result<()>) -> Result<()> {
        let mut settings = locked(&self.settings);
        change(&mut settings)?;
        settings::save(&settings)?;
        Ok(())
    }

    fn keep_account(&self, account: AccountRef) -> Result<Account> {
        let id = account.id.clone();
        self.change_settings(|settings| {
            settings.accounts.push(account);
            Ok(())
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
    fn connect(&self, account_id: &str) -> Result<Arc<Open>> {
        if let Some(open) = locked(&self.open).get(account_id) {
            return Ok(open.clone());
        }
        let account = self
            .account(account_id)?
            .ok_or_else(|| NimbraError::invalid("There is no such account."))?;
        let signed_out = || NimbraError::SignedOut {
            account: account.id.clone(),
        };
        let client: Arc<mail::Client> = match kind_of(&account) {
            AccountKind::Gmail => {
                let token = gmail::stored_refresh_token(&account.id)?.ok_or_else(signed_out)?;
                contacts::wrap(
                    gmail::Client::new(self.google()?.clone(), token, account.id.clone()),
                    &account.email,
                )
            }
            kind => {
                let credential = if kind == AccountKind::Microsoft {
                    let token =
                        microsoft::stored_refresh_token(&account.id)?.ok_or_else(signed_out)?;
                    Credential::Microsoft(Arc::new(microsoft::Tokens::new(
                        self.microsoft()?.clone(),
                        token,
                        account.id.clone(),
                    )))
                } else {
                    Credential::Password(
                        servers::stored_password(&account.id)?.ok_or_else(signed_out)?,
                    )
                };
                let servers = account.servers.clone().ok_or_else(signed_out)?;
                contacts::wrap(
                    imap_mail::Client::new(
                        account.id.clone(),
                        account.email.clone(),
                        servers,
                        credential,
                    ),
                    &account.email,
                )
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
    fn a_new_engine_has_no_accounts_and_keeps_preferences_in_its_folder() {
        let engine = engine();
        assert!(engine.accounts().is_empty());
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
            engine.list_threads("nobody".into(), Mailbox::Inbox, None, 20),
            Err(NimbraError::Invalid { .. })
        ));
        assert!(engine.remove_account("nobody".into()).is_err());
        assert!(
            engine
                .begin_microsoft_sign_in("msauth.x://auth".into(), None, None)
                .is_err()
        );
    }

    fn url_of(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }
}
