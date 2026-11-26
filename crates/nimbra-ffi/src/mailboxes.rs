//! `Engine`: mailboxes and their lists, kept on the device as the macOS app keeps them
//! (`nimbra_core::listing`), so a list opens at once and offline, then catches up.

use std::sync::Arc;

use nimbra_core::listing::{self, Meta, Row};
use nimbra_core::mail::View;
use nimbra_core::snooze;

use crate::engine::{Engine, kind_of};
use crate::error::{NimbraError, Result};
use crate::types::*;

fn rows(rows: &[Row]) -> Vec<ThreadRow> {
    rows.iter().map(ThreadRow::from).collect()
}

#[uniffi::export]
impl Engine {
    /// The mailboxes an account lists, in order: the Split Inbox (Gmail's inbox and its
    /// four categories; none for an account with its own servers), the other mailboxes,
    /// then its labels or folders as last fetched (`refresh_mailbox` and `labels` fetch
    /// them). Disk.
    pub fn mailboxes(&self, account_id: String) -> Result<Vec<MailboxEntry>> {
        let account = self
            .account(&account_id)?
            .ok_or_else(|| NimbraError::invalid("There is no such account."))?;
        let own_servers = kind_of(&account) != AccountKind::Gmail;
        let open = self.connect(&account_id)?;
        let meta: Meta = open.store.load(listing::META).unwrap_or_default();
        let entry = |view: View, section: MailboxSection| {
            Mailbox::of_view(view).map(|mailbox| MailboxEntry {
                mailbox,
                section,
                name: None,
            })
        };
        let mut entries: Vec<MailboxEntry> = listing::split_mailboxes(own_servers)
            .into_iter()
            .filter_map(|view| entry(view, MailboxSection::Split))
            .chain(
                listing::mailboxes(own_servers)
                    .into_iter()
                    .filter_map(|view| entry(view, MailboxSection::Mailboxes)),
            )
            .collect();
        entries.extend(
            meta.labels
                .iter()
                .take(listing::LABELS_SHOWN)
                .map(|label| MailboxEntry {
                    mailbox: Mailbox::Label {
                        id: label.id.clone(),
                    },
                    section: MailboxSection::Labels,
                    name: Some(label.name.clone()),
                }),
        );
        Ok(entries)
    }

    /// Unread and total threads by label, as last fetched (see `counts` for what Gmail's
    /// categories count). Disk.
    pub fn cached_counts(&self, account_id: String) -> Result<Vec<LabelCount>> {
        let open = self.connect(&account_id)?;
        let meta: Meta = open.store.load(listing::META).unwrap_or_default();
        let mut counts: Vec<LabelCount> = meta
            .counts
            .into_iter()
            .map(|(label_id, (unread, total))| LabelCount {
                label_id,
                unread,
                total,
            })
            .collect();
        counts.sort_by(|a, b| a.label_id.cmp(&b.label_id));
        Ok(counts)
    }

    /// A mailbox as kept on the device: at once, also offline. Empty when it was never
    /// listed. Disk.
    pub fn cached_threads(&self, account_id: String, mailbox: Mailbox) -> Result<Vec<ThreadRow>> {
        let open = self.connect(&account_id)?;
        let (view, label) = mailbox.view();
        Ok(rows(&listing::stored(&open.store, view, label)))
    }

    /// Brings a mailbox up to date and keeps it: from the change feed when the device
    /// knows where it was read last, else by listing its first page afresh (keeping the
    /// messages already downloaded).
    ///
    /// `threads` is always the whole mailbox as it is now kept, newest first (what
    /// `cached_threads` returns next): replace the list shown with it, never add it to
    /// what is shown. After listing afresh, that is its first page; after the change feed,
    /// every page kept so far (the first and those `load_more` added, up to 300 threads),
    /// with the changes made. Snoozed and Reminders also have the snoozes kept here.
    /// `next_page` is where the page after those threads starts: hand it to `load_more`;
    /// `None` when the server has no more. Nothing is kept when it fails. Network.
    pub fn refresh_mailbox(&self, account_id: String, mailbox: Mailbox) -> Result<ThreadPage> {
        let open = self.connect(&account_id)?;
        let (view, label) = mailbox.view();
        let refreshed = listing::refresh(&*open.client, &open.store, view, label)?;
        let mut list = refreshed.rows;
        let kept = snooze::list(&open.store);
        // As the Mac lists them: Snoozed has Gmail's own and the ones kept here; Reminders,
        // only the ones kept here. In an inbox, a reply ended a snooze.
        if matches!(view, View::Snoozed | View::Reminders) {
            for row in snooze::rows(&kept, view == View::Reminders) {
                if !list.iter().any(|m| m.id.is_some() && m.id == row.id) {
                    list.push(row);
                }
            }
            listing::sort_newest_first(&mut list);
        }
        if listing::inbox_like(view) {
            let answered = snooze::answered(&kept, &list);
            if !answered.is_empty() {
                open.store
                    .update(snooze::LIST, |list: &mut Vec<snooze::Snooze>| {
                        snooze::forget(list, &answered)
                    })?;
            }
        }
        Ok(ThreadPage {
            threads: rows(&list),
            next_page: refreshed.next_page,
        })
    }

    /// The page after what is listed (`page` is the last `next_page`), kept after it.
    /// Returns only that page's threads, without any already kept: add them after the
    /// list shown. Network.
    pub fn load_more(
        &self,
        account_id: String,
        mailbox: Mailbox,
        page: String,
    ) -> Result<ThreadPage> {
        let open = self.connect(&account_id)?;
        let (view, label) = mailbox.view();
        let (fresh, next_page) = listing::more(&*open.client, &open.store, view, label, &page)?;
        Ok(ThreadPage {
            threads: rows(&fresh),
            next_page,
        })
    }

    /// All inboxes as kept: every account's inbox, newest first, each row with its account.
    /// Disk.
    pub fn cached_all_inboxes(&self) -> Result<Vec<ThreadRow>> {
        let mut all: Vec<Row> = Vec::new();
        for account in self.accounts() {
            // One that cannot be opened (signed out, or removed meanwhile) is left out.
            let Ok(open) = self.connect(&account.id) else {
                continue;
            };
            all.extend(
                listing::stored(&open.store, View::Inbox, None)
                    .into_iter()
                    .map(|mut row| {
                        row.account = Some(account.id.clone());
                        row
                    }),
            );
        }
        listing::sort_newest_first(&mut all);
        Ok(rows(&all))
    }

    /// All inboxes: the newest `per_account` inbox threads of every account (in whole
    /// pages, as far as the list was scrolled), fetched side by side and merged newest
    /// first. An account that fails is left out and counted; all failing is the error.
    /// Network.
    pub fn all_inboxes(&self, per_account: u32) -> Result<AllInboxesPage> {
        let count = listing::all_inboxes_count(per_account as usize);
        let mut opened = Vec::new();
        for account in self.accounts() {
            opened.push((account.id.clone(), self.connect(&account.id)));
        }
        let results: Vec<(String, anyhow::Result<listing::AccountInbox<Row>>)> =
            std::thread::scope(|scope| {
                let asked: Vec<_> = opened
                    .iter()
                    .map(|(id, open)| {
                        let open = open.as_ref().ok().map(Arc::clone);
                        let id = id.clone();
                        scope.spawn(move || {
                            let result = match open {
                                Some(open) => listing::account_inbox(&*open.client, &id, count),
                                None => Err(anyhow::anyhow!("not connected")),
                            };
                            (id, result)
                        })
                    })
                    .collect();
                asked
                    .into_iter()
                    .filter_map(|handle| handle.join().ok())
                    .collect()
            });
        let asked = results.len();
        let all = listing::all_inboxes(results);
        if asked > 0 && all.failed == asked {
            return Err(all
                .first_error
                .map(NimbraError::from)
                .unwrap_or(NimbraError::Offline));
        }
        let mut unread: Vec<LabelCount> = all
            .unread
            .into_iter()
            .map(|(label_id, unread)| LabelCount {
                label_id,
                unread,
                total: 0,
            })
            .collect();
        unread.sort_by(|a, b| a.label_id.cmp(&b.label_id));
        Ok(AllInboxesPage {
            threads: rows(&all.rows),
            unread,
            failed_accounts: all.failed as u32,
        })
    }

    /// A thread's messages, parsed: text blocks, the original HTML, attachments. They are
    /// kept with its row, so it opens at once next time (`cached_thread`). Network.
    pub fn read_thread(&self, account_id: String, thread_id: String) -> Result<MailThread> {
        let open = self.connect(&account_id)?;
        let messages = open.client.thread(&thread_id)?;
        let thread = MailThread {
            id: thread_id.clone(),
            messages: messages.iter().map(MailMessage::from).collect(),
        };
        if listing::keep_thread(&open.store, &thread_id, messages).is_err() {
            eprintln!("nimbra: could not keep a thread on the device");
        }
        Ok(thread)
    }

    /// A thread as kept on the device, when its messages were downloaded: at once, also
    /// offline. `None`: read it with `read_thread`. Disk.
    pub fn cached_thread(
        &self,
        account_id: String,
        thread_id: String,
    ) -> Result<Option<MailThread>> {
        let open = self.connect(&account_id)?;
        Ok(listing::kept_thread(&open.store, &thread_id)
            .as_ref()
            .map(MailThread::from))
    }
}
