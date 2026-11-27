//! A mail server in memory, for tests here and in the apps (`test-support`): threads with
//! labels, a scripted change feed, and a record of what was asked of it. Nothing leaves the
//! process.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use anyhow::{Result, anyhow};

use crate::mail::{
    Change, Changes, Draft, HistoryExpired, Label, Message, Offline, Outgoing, Person, Provider,
    Summary, View,
};
use crate::store::Store;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The change feed point that is too old (`HistoryExpired`).
pub const EXPIRED: &str = "expired";

/// A provider in memory.
pub struct Fake {
    pub email: String,
    /// Every thread, as rows.
    pub threads: Mutex<Vec<Summary>>,
    /// What the change feed says next, whatever point it is read from (but `EXPIRED`).
    pub changes: Mutex<Changes>,
    /// The feed's point now.
    pub latest: Mutex<String>,
    /// Labels.
    pub labels: Mutex<Vec<Label>>,
    /// Every change asked for, in order.
    pub asked: Mutex<Vec<(String, String)>>,
    /// Messages sent.
    pub sent: Mutex<Vec<Outgoing>>,
    /// Drafts by id.
    pub drafts: Mutex<HashMap<String, Outgoing>>,
    /// Everything fails as offline.
    pub offline: AtomicBool,
    /// `wait_for_change` says there was one.
    pub changed: AtomicBool,
    serial: AtomicU64,
}

impl Fake {
    pub fn new(email: &str) -> Arc<Self> {
        Arc::new(Fake {
            email: email.to_string(),
            threads: Mutex::new(Vec::new()),
            changes: Mutex::new(Changes::default()),
            latest: Mutex::new("1".into()),
            labels: Mutex::new(Vec::new()),
            asked: Mutex::new(Vec::new()),
            sent: Mutex::new(Vec::new()),
            drafts: Mutex::new(HashMap::new()),
            offline: AtomicBool::new(false),
            changed: AtomicBool::new(false),
            serial: AtomicU64::new(0),
        })
    }

    /// A thread row with these labels, from `sender`, at `at`.
    pub fn thread(id: &str, labels: &[&str], at: i64) -> Summary {
        Summary {
            id: id.into(),
            sender: format!("Sender {id}"),
            sender_address: format!("{id}@example.com"),
            brand_domain: None,
            subject: format!("Subject {id}"),
            snippet: format!("Snippet {id}"),
            timestamp_ms: at,
            message_count: 1,
            unread: labels.contains(&"UNREAD"),
            starred: labels.contains(&"STARRED"),
            labels: labels.iter().map(|l| l.to_string()).collect(),
            message_labels: vec![labels.iter().map(|l| l.to_string()).collect()],
            senders: vec![format!("{id}@example.com")],
            people: Vec::new(),
        }
    }

    pub fn add(&self, summary: Summary) {
        let mut threads = locked(&self.threads);
        threads.retain(|t| t.id != summary.id);
        threads.push(summary);
    }

    pub fn labels_of(&self, id: &str) -> Vec<String> {
        locked(&self.threads)
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.labels.clone())
            .unwrap_or_default()
    }

    /// The changes asked for, as `(thread, what)`.
    pub fn asked(&self) -> Vec<(String, String)> {
        locked(&self.asked).clone()
    }

    fn online(&self) -> Result<()> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(Offline.into());
        }
        Ok(())
    }

    fn edit(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        let mut threads = locked(&self.threads);
        let thread = threads
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| anyhow!("Gmail error 404: no such thread"))?;
        thread.labels.retain(|l| !remove.contains(&l.as_str()));
        for label in add {
            if !thread.labels.iter().any(|l| l == label) {
                thread.labels.push(label.to_string());
            }
        }
        thread.message_labels = vec![thread.labels.clone()];
        thread.unread = thread.labels.iter().any(|l| l == "UNREAD");
        thread.starred = thread.labels.iter().any(|l| l == "STARRED");
        Ok(())
    }
}

impl Provider for Fake {
    fn profile(&self) -> Result<(String, String)> {
        self.online()?;
        Ok((self.email.clone(), locked(&self.latest).clone()))
    }
    fn writes(&self) -> u64 {
        locked(&self.asked).len() as u64
    }
    fn forget_rows(&self) {}
    fn keep_rows_in(&self, _: &Arc<Store>) {}
    fn history(&self, start: &str) -> Result<Changes> {
        self.online()?;
        if start == EXPIRED {
            return Err(HistoryExpired.into());
        }
        let changes = std::mem::take(&mut *locked(&self.changes));
        let latest = if changes.latest.is_empty() {
            locked(&self.latest).clone()
        } else {
            changes.latest.clone()
        };
        *locked(&self.latest) = latest.clone();
        Ok(Changes { latest, ..changes })
    }
    fn wait_for_change(&self, _: std::time::Duration) -> bool {
        self.changed.swap(false, Ordering::SeqCst)
    }
    fn threads_page(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Summary>, Option<String>)> {
        self.online()?;
        let mut threads: Vec<Summary> = locked(&self.threads)
            .iter()
            .filter(|t| match view {
                View::Search => label_id.is_some_and(|q| t.subject.contains(q)),
                View::Snoozed | View::Reminders => false,
                view => view.takes(t, label_id),
            })
            .cloned()
            .collect();
        threads.sort_by_key(|t| std::cmp::Reverse(t.timestamp_ms));
        let from: usize = page.map_or(0, |p| p.parse().unwrap_or(0));
        let next = (from + limit < threads.len()).then(|| (from + limit).to_string());
        Ok((threads.into_iter().skip(from).take(limit).collect(), next))
    }
    fn page_after(
        &self,
        view: View,
        label_id: Option<&str>,
        count: usize,
    ) -> Result<Option<String>> {
        let (all, _) = self.threads_page(view, label_id, usize::MAX / 2, None)?;
        Ok((count < all.len()).then(|| count.to_string()))
    }
    fn summary(&self, id: &str, _: bool) -> Result<Summary> {
        self.online()?;
        locked(&self.threads)
            .iter()
            .find(|t| t.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("Gmail error 404: no such thread"))
    }
    fn thread(&self, id: &str) -> Result<Vec<Message>> {
        let summary = self.summary(id, false)?;
        let from = Person {
            name: summary.sender.clone(),
            address: format!("{id}@example.com"),
        };
        Ok(vec![Message {
            from: from.clone(),
            to: vec![Person {
                name: String::new(),
                address: self.email.clone(),
            }],
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: None,
            attachments: Vec::new(),
            unsubscribe: None,
            address: from.address.clone(),
            message_id: format!("<{id}@example.com>"),
            others: Vec::new(),
            sender: summary.sender.clone(),
            snippet: summary.snippet.clone(),
            timestamp_ms: summary.timestamp_ms,
            blocks: crate::rich::from_text(vec![format!("Body of {id}")]),
            html: None,
        }])
    }
    fn download(&self, _: &str, _: &str) -> Result<Vec<u8>> {
        self.online()?;
        Ok(b"file".to_vec())
    }
    fn change(&self, id: &str, change: Change) -> Result<()> {
        self.online()?;
        locked(&self.asked).push((id.to_string(), format!("{change:?}")));
        let (add, remove): (&[&str], &[&str]) = match change {
            Change::Archive => (&[], &["INBOX"]),
            Change::Unarchive => (&["INBOX"], &[]),
            Change::Trash => (&["TRASH"], &["INBOX"]),
            Change::Untrash => (&[], &["TRASH"]),
            Change::Star => (&["STARRED"], &[]),
            Change::Unstar => (&[], &["STARRED"]),
            Change::MarkRead => (&[], &["UNREAD"]),
            Change::MarkUnread => (&["UNREAD"], &[]),
            Change::Spam => (&["SPAM"], &["INBOX"]),
            Change::NotSpam => (&["INBOX"], &["SPAM"]),
        };
        self.edit(id, add, remove)
    }
    fn draft_for_thread(&self, thread_id: &str) -> Result<Draft> {
        Err(anyhow!("Gmail error 404: no draft in {}", thread_id.len()))
    }
    fn save_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        self.online()?;
        let id = id
            .map(String::from)
            .unwrap_or_else(|| format!("draft-{}", self.serial.fetch_add(1, Ordering::SeqCst)));
        locked(&self.drafts).insert(id.clone(), outgoing.clone());
        Ok(id)
    }
    fn send_draft(&self, id: &str, outgoing: &Outgoing) -> Result<()> {
        self.online()?;
        locked(&self.drafts).remove(id);
        locked(&self.sent).push(outgoing.clone());
        Ok(())
    }
    fn keep_as_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        self.save_draft(id, outgoing)
    }
    fn send_saved_draft(&self, id: &str) -> Result<()> {
        self.online()?;
        let draft = locked(&self.drafts)
            .remove(id)
            .ok_or_else(|| anyhow!("Gmail error 404: no such draft"))?;
        locked(&self.sent).push(draft);
        Ok(())
    }
    fn delete_draft(&self, id: &str) -> Result<()> {
        self.online()?;
        locked(&self.drafts).remove(id);
        Ok(())
    }
    fn send_message(&self, outgoing: &Outgoing) -> Result<()> {
        self.online()?;
        locked(&self.sent).push(outgoing.clone());
        Ok(())
    }
    fn delete_thread(&self, id: &str) -> Result<()> {
        self.online()?;
        locked(&self.threads).retain(|t| t.id != id);
        Ok(())
    }
    fn labels(&self) -> Result<Vec<Label>> {
        self.online()?;
        Ok(locked(&self.labels).clone())
    }
    fn create_label(&self, name: &str) -> Result<Label> {
        self.online()?;
        let label = Label {
            id: format!("Label_{}", self.serial.fetch_add(1, Ordering::SeqCst)),
            name: name.to_string(),
        };
        locked(&self.labels).push(label.clone());
        Ok(label)
    }
    fn rename_label(&self, id: &str, name: &str) -> Result<()> {
        self.online()?;
        for label in locked(&self.labels).iter_mut().filter(|l| l.id == id) {
            label.name = name.to_string();
        }
        Ok(())
    }
    fn delete_label(&self, id: &str) -> Result<()> {
        self.online()?;
        locked(&self.labels).retain(|l| l.id != id);
        Ok(())
    }
    fn add_label(&self, id: &str, label_id: &str) -> Result<()> {
        self.relabel(id, &[label_id], &[])
    }
    fn remove_label(&self, id: &str, label_id: &str) -> Result<()> {
        self.relabel(id, &[], &[label_id])
    }
    fn relabel(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        self.online()?;
        locked(&self.asked).push((id.to_string(), format!("relabel +{add:?} -{remove:?}")));
        self.edit(id, add, remove)
    }
    fn counts(&self, label_ids: &[String]) -> HashMap<String, (u32, u32)> {
        let threads = locked(&self.threads);
        label_ids
            .iter()
            .map(|id| {
                let with: Vec<&Summary> =
                    threads.iter().filter(|t| t.labels.contains(id)).collect();
                let unread = with.iter().filter(|t| t.unread).count() as u32;
                (id.clone(), (unread, with.len() as u32))
            })
            .collect()
    }
}
