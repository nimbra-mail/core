//! Mailboxes as lists of rows, and what the encrypted store keeps of them: the newest
//! threads of each mailbox (with the full text of the newest), so an app opens straight
//! into its mail and works offline, and where each mailbox's change feed was last read.
//!
//! The rows here are what is stored and what both apps list. The macOS app draws them
//! through its own `data::Mail`, which is a `Row` with display fields beside it
//! (`Listed`); the iOS app lists them as they are.
//!
//! Fetching is blocking: call it from a background thread.

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::mail::{self, Label, Summary, View};
use crate::rich::{self, Block};

/// The newest threads kept of a mailbox.
pub const KEEP_THREADS: usize = 300;
/// The newest threads of a mailbox kept with their full text; older ones are downloaded
/// again when opened.
pub const KEEP_BODIES: usize = 100;
/// Threads asked for in a first page.
pub const PAGE: usize = 30;
/// The record the account's sidebar state and sync points are kept under.
pub const META: &str = "meta";
/// More changed threads than this in one look: listing again is cheaper than reading each.
pub const MOST_CHANGES: usize = 40;

// ------------------------------------------------------------------ rows

/// A thread's messages, shared between the copies of its row (the list, the cache of each
/// mailbox, what is being saved) instead of copied for each. Changed in place only where no
/// other copy has it; stored as the value itself.
#[derive(Default, Debug, PartialEq)]
pub struct Shared<T>(Arc<T>);

impl<T> Shared<T> {
    /// Where the value is, to tell copies that share it apart from ones that do not.
    pub fn as_ptr(&self) -> *const T {
        Arc::as_ptr(&self.0)
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Shared(self.0.clone())
    }
}

impl<T> Deref for Shared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Clone> DerefMut for Shared<T> {
    fn deref_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.0)
    }
}

impl<T> From<T> for Shared<T> {
    fn from(value: T) -> Self {
        Shared(Arc::new(value))
    }
}

impl<'a, T> IntoIterator for &'a Shared<T>
where
    &'a T: IntoIterator,
{
    type Item = <&'a T as IntoIterator>::Item;
    type IntoIter = <&'a T as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        (&*self.0).into_iter()
    }
}

impl<T: Serialize> Serialize for Shared<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Shared<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Shared::from)
    }
}

/// What a message says about itself, for the header of a message being read.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub from: mail::Person,
    pub to: Vec<mail::Person>,
    pub cc: Vec<mail::Person>,
    pub reply_to: Option<mail::Person>,
    pub date_ms: i64,
    pub attachments: Vec<mail::Attachment>,
    pub unsubscribe: Option<String>,
    /// The RFC 5322 Message-ID, to reply to this message specifically.
    pub message_id: String,
}

impl Header {
    pub fn from_message(message: &mail::Message) -> Self {
        Header {
            from: message.from.clone(),
            to: message.to.clone(),
            cc: message.cc.clone(),
            reply_to: message.reply_to.clone(),
            date_ms: message.timestamp_ms,
            attachments: message.attachments.clone(),
            unsubscribe: message.unsubscribe.clone(),
            message_id: message.message_id.clone(),
        }
    }

    /// Who replies go to: Reply-To if set, else the sender.
    pub fn reply_address(&self) -> &str {
        self.reply_to
            .as_ref()
            .map_or(self.from.address.as_str(), |p| p.address.as_str())
    }

    /// Everyone on To and Cc, for reply-all.
    pub fn everyone(&self) -> Vec<String> {
        self.to
            .iter()
            .chain(&self.cc)
            .map(|p| p.address.clone())
            .collect()
    }
}

/// An older message of a thread, shown collapsed above the latest one.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Earlier {
    pub sender: String,
    pub snippet: String,
    pub blocks: Vec<Block>,
    /// Opened from its one line, by a click.
    #[serde(default)]
    pub expanded: bool,
    #[serde(default)]
    pub header: Header,
}

/// One thread in a mailbox's list: its row, and once fetched its messages.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Row {
    /// The provider's thread id; `None` for built-in sample data.
    pub id: Option<String>,
    pub sender: String,
    pub subject: String,
    pub snippet: String,
    /// How many messages, as shown beside the row when there is more than one.
    pub thread: Option<String>,
    pub unread: bool,
    pub starred: bool,
    /// Who wrote in it, once its messages are fetched ("Ana, Ben · 3 messages").
    pub participants: String,
    /// Older messages, newest first.
    pub earlier: Shared<Vec<Earlier>>,
    /// The latest message's text.
    pub body: Shared<Vec<Block>>,
    /// Whether `body` and `earlier` have been fetched.
    pub loaded: bool,
    /// Who and what a reply answers (the latest message), once the thread is loaded.
    pub reply: Option<(String, mail::ReplyTo)>,
    /// The other recipients of the latest message, for reply-all.
    pub reply_all: Vec<String>,
    /// The latest message's original HTML.
    pub html: Option<String>,
    /// When the latest message arrived.
    pub timestamp_ms: i64,
    /// Headers of the latest message (sender, recipients, date, attachments).
    pub header: Header,
    /// The provider's labels on the thread.
    pub labels: Vec<String>,
    /// The account this thread belongs to, when the list mixes accounts (All inboxes).
    pub account: Option<String>,
}

impl Row {
    /// A list row for a thread. Its messages are filled in by [`Row::fill`].
    pub fn from_summary(summary: Summary) -> Self {
        Row {
            id: Some(summary.id),
            participants: summary.sender.clone(),
            sender: summary.sender,
            subject: summary.subject,
            snippet: summary.snippet,
            timestamp_ms: summary.timestamp_ms,
            thread: (summary.message_count > 1).then(|| summary.message_count.to_string()),
            unread: summary.unread,
            starred: summary.starred,
            labels: summary.labels,
            ..Row::default()
        }
    }

    /// Fills in the thread once its messages (oldest first) have been fetched.
    pub fn fill(&mut self, mut messages: Vec<mail::Message>) {
        let count = messages.len();
        let mut senders: Vec<&str> = Vec::new();
        for message in &messages {
            if !senders.contains(&message.sender.as_str()) {
                senders.push(&message.sender);
            }
        }
        self.participants = if count > 1 {
            format!("{} · {count} messages", senders.join(", "))
        } else {
            senders.join(", ")
        };
        if let Some(latest) = messages.pop() {
            self.header = Header::from_message(&latest);
            self.reply_all = latest.others.clone();
            self.reply = self.id.clone().map(|thread_id| {
                (
                    latest.address.clone(),
                    mail::ReplyTo {
                        thread_id,
                        message_id: latest.message_id.clone(),
                    },
                )
            });
            self.html = latest.html;
            self.body = if latest.blocks.is_empty() {
                rich::from_text(vec![latest.snippet])
            } else {
                latest.blocks
            }
            .into();
        }
        self.earlier = messages
            .into_iter()
            .rev()
            .map(|message| Earlier {
                header: Header::from_message(&message),
                sender: message.sender,
                snippet: message.snippet,
                blocks: message.blocks,
                expanded: false,
            })
            .collect::<Vec<_>>()
            .into();
        self.loaded = true;
    }

    /// Drops its messages (kept for older threads, or with a snooze): they are downloaded
    /// again when it is opened.
    pub fn without_content(&self) -> Row {
        Row {
            loaded: false,
            body: Default::default(),
            earlier: Default::default(),
            html: None,
            ..self.clone()
        }
    }
}

/// A list row as an app holds it: a `Row`, perhaps with what it needs to draw it. The
/// listing functions work on any of them, so both apps run the same code.
pub trait Listed: AsRef<Row> + AsMut<Row> + From<Row> {}

impl<T: AsRef<Row> + AsMut<Row> + From<Row>> Listed for T {}

impl AsRef<Row> for Row {
    fn as_ref(&self) -> &Row {
        self
    }
}

impl AsMut<Row> for Row {
    fn as_mut(&mut self) -> &mut Row {
        self
    }
}

/// Combines a freshly fetched listing with what is already in memory, so thread contents
/// that were already downloaded are not fetched again.
///
/// A thread keeps its cached messages only while its snippet and message count are
/// unchanged; a new reply changes both, which makes it load again.
pub fn merge<T: Listed>(cached: &[T], fresh: Vec<T>) -> Vec<T> {
    // Thread ids are each account's own (All inboxes mixes accounts).
    let loaded: HashMap<(&str, Option<&str>), &Row> = cached
        .iter()
        .map(AsRef::as_ref)
        .filter(|old| old.loaded)
        .filter_map(|old| Some(((old.id.as_deref()?, old.account.as_deref()), old)))
        .collect();
    fresh
        .into_iter()
        .map(|mut fresh| {
            let mail = fresh.as_mut();
            let key = mail.id.as_deref().map(|id| (id, mail.account.as_deref()));
            if let Some(old) = key.and_then(|key| loaded.get(&key))
                && old.snippet == mail.snippet
                && old.thread == mail.thread
            {
                mail.body = old.body.clone();
                mail.earlier = old.earlier.clone();
                mail.participants = old.participants.clone();
                mail.reply = old.reply.clone();
                mail.header = old.header.clone();
                mail.reply_all = old.reply_all.clone();
                mail.html = old.html.clone();
                mail.loaded = true;
            }
            fresh
        })
        .collect()
}

/// What is kept of a list: the newest `KEEP_THREADS`, the newest `KEEP_BODIES` with their
/// messages. Copies of the rows share their messages: this is no copy of the mail itself.
pub fn kept<'a>(rows: impl IntoIterator<Item = &'a Row>) -> Vec<Row> {
    rows.into_iter()
        .take(KEEP_THREADS)
        .enumerate()
        .map(|(index, row)| {
            if index >= KEEP_BODIES && row.loaded {
                row.without_content()
            } else {
                row.clone()
            }
        })
        .collect()
}

/// Newest first, as every mailbox is listed.
pub fn sort_newest_first<T: Listed>(list: &mut [T]) {
    list.sort_by_key(|row| std::cmp::Reverse(row.as_ref().timestamp_ms));
}

// ------------------------------------------------------------------ records

/// A stable number per mailbox: its record in the store (and the Mac's element ids).
pub fn view_number(view: View) -> usize {
    match view {
        View::AllInboxes => 99,
        View::Inbox => 0,
        View::Primary => 1,
        View::Updates => 2,
        View::Promotions => 3,
        View::Social => 4,
        View::Starred => 5,
        View::Snoozed => 6,
        View::Reminders => 15,
        View::Drafts => 7,
        View::Sent => 8,
        View::Done => 9,
        View::Search => 10,
        View::AllMail => 11,
        View::Important => 12,
        View::Spam => 13,
        View::Trash => 14,
        View::Label(index) => 100 + index,
    }
}

/// The store record a mailbox is kept under. A label's is named by its id (`label_id`),
/// which outlives its place in the list; without one it goes by its place.
pub fn record(view: View, label_id: Option<&str>) -> String {
    match (view, label_id) {
        (View::Label(_), Some(id)) => format!(
            "label-{}",
            id.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .take(50)
                .collect::<String>()
        ),
        (view, _) => format!("view-{}", view_number(view)),
    }
}

/// The account's sidebar state and sync points, kept beside its mailboxes.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    /// The address the store was saved for: another one starts it clean.
    pub account: String,
    pub initials: String,
    /// Unread and total threads by label id.
    pub counts: HashMap<String, (u32, u32)>,
    pub labels: Vec<Label>,
    /// Where each mailbox's change feed was last read, by record.
    #[serde(default)]
    pub synced_to: HashMap<String, String>,
}

/// The labels counted for the sidebar: the system mailboxes, then the first few labels.
pub fn count_ids<'a>(labels: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    [
        "INBOX",
        "DRAFT",
        "CATEGORY_PERSONAL",
        "CATEGORY_UPDATES",
        "CATEGORY_PROMOTIONS",
        "CATEGORY_SOCIAL",
    ]
    .into_iter()
    .chain(labels.into_iter().take(8))
    .map(String::from)
    .collect()
}

// ------------------------------------------------------------------ fetching

/// A mailbox listed afresh (`first_page`).
pub struct FirstPage {
    /// The account's address, to tell a store saved for another apart.
    pub email: String,
    /// Where the change feed is: read before the list, so nothing that changes meanwhile
    /// is missed by the next sync.
    pub history_id: String,
    pub threads: Vec<Summary>,
    /// The labels, when they were asked for (none were known).
    pub labels: Option<Vec<Label>>,
    /// The sidebar counts, when they were asked for. Empty when not.
    pub counts: HashMap<String, (u32, u32)>,
    pub next_page: Option<String>,
}

/// Lists a mailbox's first `count` threads afresh. `label_id` is the label (or the search
/// words). `known_labels` are counted when the labels are not asked for again. Blocking.
pub fn first_page(
    client: &mail::Client,
    view: View,
    label_id: Option<&str>,
    count: usize,
    need_labels: bool,
    known_labels: &[String],
    counts_wanted: bool,
) -> Result<FirstPage> {
    let (email, history_id) = client.profile()?;
    let (threads, next_page) = client.threads_page(view, label_id, count, None)?;
    // Labels are a nicety; the mailbox still loads without them.
    let labels = need_labels.then(|| client.labels().unwrap_or_default());
    let ids = match &labels {
        Some(labels) => count_ids(labels.iter().map(|l| l.id.as_str())),
        None => count_ids(known_labels.iter().map(String::as_str)),
    };
    let counts = if counts_wanted || need_labels {
        client.counts(&ids)
    } else {
        HashMap::new()
    };
    Ok(FirstPage {
        email,
        history_id,
        threads,
        labels,
        counts,
        next_page,
    })
}

/// What changed in a mailbox since its sync point (`sync`).
pub struct Synced {
    /// The next sync point.
    pub latest: String,
    /// Each changed thread with its row now; `None` when it is gone.
    pub updates: Vec<(String, Option<Summary>)>,
    /// The sidebar counts, when asked for and something changed.
    pub counts: Option<HashMap<String, (u32, u32)>>,
    /// Where the page after the `listed` rows starts, when asked for (`Some(None)`: there
    /// is none).
    pub page: Option<Option<String>>,
}

/// Reads the change feed from `start` and the fresh row of every thread it names. Too many
/// changes is `HistoryExpired`: the mailbox is listed again instead. `find_page` also asks
/// where the page after the `listed` rows starts (a list kept on the device has no token
/// for it). Blocking.
#[allow(clippy::too_many_arguments)]
pub fn sync(
    client: &mail::Client,
    start: &str,
    view: View,
    label_id: Option<&str>,
    find_page: bool,
    listed: usize,
    counts_wanted: bool,
    count_ids: &[String],
) -> Result<Synced> {
    let changes = client.history(start)?;
    if changes.threads.len() > MOST_CHANGES {
        return Err(mail::HistoryExpired.into());
    }
    let recipient = matches!(view, View::Sent | View::Drafts);
    let mut updates = Vec::new();
    for id in &changes.threads {
        match client.summary(id, recipient) {
            Ok(summary) => updates.push((id.clone(), Some(summary))),
            Err(error) if error.to_string().starts_with("Gmail error 404") => {
                updates.push((id.clone(), None))
            }
            Err(error) => return Err(error),
        }
    }
    let counts = (counts_wanted && !updates.is_empty()).then(|| client.counts(count_ids));
    let page = if !find_page {
        None
    } else if (1..=500).contains(&listed) {
        client.page_after(view, label_id, listed).ok()
    } else {
        Some(None)
    };
    Ok(Synced {
        latest: changes.latest,
        updates,
        counts,
        page,
    })
}

/// Applies a sync's updates to a list: each changed thread leaves it, and comes back where
/// its date puts it if it still belongs in the mailbox.
pub fn apply_updates<T: Listed>(
    list: &mut Vec<T>,
    updates: Vec<(String, Option<Summary>)>,
    view: View,
    label_id: Option<&str>,
) {
    for (id, summary) in updates {
        list.retain(|row| row.as_ref().id.as_deref() != Some(id.as_str()));
        if let Some(summary) = summary
            && view.takes(&summary, label_id)
        {
            list.push(T::from(Row::from_summary(summary)));
        }
    }
    sort_newest_first(list);
}

// ------------------------------------------------------------------ kept mailboxes

/// A mailbox brought up to date in the store (`refresh`).
pub struct Refreshed {
    /// What it lists now, newest first, as kept.
    pub rows: Vec<Row>,
    /// Where the next page starts, when there is one.
    pub next_page: Option<String>,
    /// It was listed afresh rather than patched from the change feed.
    pub relisted: bool,
}

/// A mailbox as the store keeps it, and the account's kept state. Search results are never
/// kept. Blocking (disk).
pub fn stored(store: &crate::store::Store, view: View, label_id: Option<&str>) -> Vec<Row> {
    if matches!(view, View::Search | View::AllInboxes) {
        return Vec::new();
    }
    store.load(&record(view, label_id)).unwrap_or_default()
}

/// Brings a kept mailbox up to date, as the macOS app does for the one it shows: from the
/// change feed when the store knows where it was last read and the mailbox can follow it,
/// else by listing its first page afresh, keeping the messages already downloaded. The
/// store is written (`kept`) and its sync point and counts with it. Blocking (network).
pub fn refresh(
    client: &mail::Client,
    store: &crate::store::Store,
    view: View,
    label_id: Option<&str>,
) -> Result<Refreshed> {
    let name = record(view, label_id);
    let mut meta: Meta = store.load(META).unwrap_or_default();
    let cached: Vec<Row> = stored(store, view, label_id);
    let ids = count_ids(meta.labels.iter().map(|l| l.id.as_str()));
    let start = meta.synced_to.get(&name).cloned();
    if view.syncs(label_id)
        && !cached.is_empty()
        && let Some(start) = start
    {
        match sync(
            client,
            &start,
            view,
            label_id,
            true,
            cached.len(),
            true,
            &ids,
        ) {
            Ok(synced) => {
                let mut rows = cached;
                apply_updates(&mut rows, synced.updates, view, label_id);
                meta.synced_to.insert(name.clone(), synced.latest);
                if let Some(counts) = synced.counts.filter(|c| !c.is_empty()) {
                    meta.counts = counts;
                }
                let rows = kept(&rows);
                store.save(&name, &rows)?;
                store.save(META, &meta)?;
                return Ok(Refreshed {
                    rows,
                    next_page: synced.page.flatten(),
                    relisted: false,
                });
            }
            Err(error) if error.is::<mail::HistoryExpired>() => {}
            Err(error) => return Err(error),
        }
    }
    let known: Vec<String> = meta.labels.iter().map(|l| l.id.clone()).collect();
    let page = first_page(
        client,
        view,
        label_id,
        PAGE,
        meta.labels.is_empty(),
        &known,
        true,
    )?;
    // Another account than the one the store was kept for: it starts clean.
    let cached = if meta.account.contains('@') && meta.account != page.email {
        for kept in store
            .names("view-")
            .into_iter()
            .chain(store.names("label-"))
        {
            store.remove(&kept);
        }
        meta = Meta::default();
        Vec::new()
    } else {
        cached
    };
    let fresh: Vec<Row> = page.threads.into_iter().map(Row::from_summary).collect();
    let rows = kept(&merge(&cached, fresh));
    meta.initials = page
        .email
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    meta.account = page.email;
    if view.syncs(label_id) {
        meta.synced_to.insert(name.clone(), page.history_id);
    }
    if !page.counts.is_empty() {
        meta.counts = page.counts;
    }
    if let Some(labels) = page.labels {
        meta.labels = labels;
    }
    store.save(&name, &rows)?;
    store.save(META, &meta)?;
    Ok(Refreshed {
        rows,
        next_page: page.next_page,
        relisted: true,
    })
}

/// The next page of a kept mailbox from `page`, put after what is kept (without threads
/// already there) and kept with it. The rows of that page, and where the one after starts.
/// Blocking (network).
pub fn more(
    client: &mail::Client,
    store: &crate::store::Store,
    view: View,
    label_id: Option<&str>,
    page: &str,
) -> Result<(Vec<Row>, Option<String>)> {
    let (threads, next) = client.threads_page(view, label_id, PAGE, Some(page))?;
    let mut rows = stored(store, view, label_id);
    let known: std::collections::HashSet<String> =
        rows.iter().filter_map(|row| row.id.clone()).collect();
    let fresh: Vec<Row> = threads
        .into_iter()
        .filter(|summary| !known.contains(&summary.id))
        .map(Row::from_summary)
        .collect();
    if !matches!(view, View::Search | View::AllInboxes) {
        rows.extend(fresh.iter().cloned());
        store.save(&record(view, label_id), &kept(&rows))?;
    }
    Ok((fresh, next))
}

/// Keeps a thread's messages with its row in every mailbox the store lists it in, so it
/// opens at once, also offline. Blocking (disk).
pub fn keep_thread(
    store: &crate::store::Store,
    thread_id: &str,
    messages: Vec<mail::Message>,
) -> Result<()> {
    let mut messages = Some(messages);
    let mut filled: Option<Row> = None;
    for name in store
        .names("view-")
        .into_iter()
        .chain(store.names("label-"))
    {
        let Some(mut rows) = store.load::<Vec<Row>>(&name) else {
            continue;
        };
        let Some(row) = rows
            .iter_mut()
            .take(KEEP_BODIES)
            .find(|row| row.id.as_deref() == Some(thread_id))
        else {
            continue;
        };
        match (&filled, messages.take()) {
            (Some(done), _) => {
                row.participants = done.participants.clone();
                row.earlier = done.earlier.clone();
                row.body = done.body.clone();
                row.reply = done.reply.clone();
                row.reply_all = done.reply_all.clone();
                row.html = done.html.clone();
                row.header = done.header.clone();
                row.loaded = true;
            }
            (None, Some(messages)) => {
                row.fill(messages);
                filled = Some(row.clone());
            }
            (None, None) => continue,
        }
        store.save(&name, &rows)?;
    }
    Ok(())
}

/// A thread as kept with its row, when its messages are (`keep_thread`). Blocking (disk).
pub fn kept_thread(store: &crate::store::Store, thread_id: &str) -> Option<Row> {
    store
        .names("view-")
        .into_iter()
        .chain(store.names("label-"))
        .filter_map(|name| store.load::<Vec<Row>>(&name))
        .flatten()
        .find(|row| row.loaded && row.id.as_deref() == Some(thread_id))
}

// ------------------------------------------------------------------ mailboxes

/// The mailboxes that are an inbox, one account's or every account's: Done archives there,
/// Snooze and Move take the thread out.
pub fn inbox_like(view: View) -> bool {
    matches!(
        view,
        View::Inbox
            | View::AllInboxes
            | View::Primary
            | View::Updates
            | View::Promotions
            | View::Social
    )
}

/// What Move to Inbox does from `view`: out of Spam or Trash, else out of the archive.
pub fn to_inbox(view: View) -> mail::Change {
    match view {
        View::Spam => mail::Change::NotSpam,
        View::Trash => mail::Change::Untrash,
        _ => mail::Change::Unarchive,
    }
}

/// A thread's row as some kept mailbox lists it. Blocking (disk).
pub fn find_kept(store: &crate::store::Store, thread_id: &str) -> Option<Row> {
    store
        .names("view-")
        .into_iter()
        .chain(store.names("label-"))
        .filter_map(|name| store.load::<Vec<Row>>(&name))
        .flatten()
        .find(|row| row.id.as_deref() == Some(thread_id))
}

/// The same labels under the same names, in any order: a label made or renamed elsewhere
/// is a change.
pub fn same_labels(a: &[Label], b: &[Label]) -> bool {
    a.len() == b.len()
        && a.iter()
            .all(|x| b.iter().any(|y| y.id == x.id && y.name == x.name))
}

/// Labels as they are listed: by name, in any case.
pub fn sort_labels(labels: &mut [Label]) {
    labels.sort_by_key(|l| l.name.to_lowercase());
}

/// The label already called `name` (in any case): a new one by that name is that one.
pub fn label_named<'a>(labels: &'a [Label], name: &str) -> Option<&'a Label> {
    labels
        .iter()
        .find(|l| l.name.eq_ignore_ascii_case(name.trim()))
}

/// The most labels an account lists.
pub const LABELS_SHOWN: usize = 40;

/// The Split Inbox, in its default order: the inbox and Gmail's four categories. An account
/// with its own servers (IMAP) has none: its server has no categories.
pub fn split_mailboxes(own_servers: bool) -> Vec<View> {
    if own_servers {
        return Vec::new();
    }
    vec![
        View::Inbox,
        View::Primary,
        View::Updates,
        View::Promotions,
        View::Social,
    ]
}

/// The other mailboxes, in their default order. An account with its own servers lists its
/// inbox here (it has no split), and has no Important.
pub fn mailboxes(own_servers: bool) -> Vec<View> {
    let mut views = Vec::new();
    if own_servers {
        views.push(View::Inbox);
    }
    views.push(View::Starred);
    if !own_servers {
        views.push(View::Important);
    }
    views.extend([
        View::Snoozed,
        View::Reminders,
        View::Drafts,
        View::Sent,
        View::Done,
        View::AllMail,
        View::Spam,
        View::Trash,
    ]);
    views
}

// ------------------------------------------------------------------ all inboxes

/// One account's part of All inboxes: its rows, where its next page starts, and its
/// unread count.
pub type AccountInbox<T> = (Vec<T>, Option<String>, u32);

/// An account's next page of All inboxes: by account id, the page asked for, and what came.
pub type MoreOfAccount = (String, String, Result<(Vec<Summary>, Option<String>)>);

/// The most of one account's inbox All inboxes lists at once.
pub const ALL_INBOXES_MOST: usize = 480;

/// How many of an account's inbox threads All inboxes asks for, when `listed` of them are
/// listed now: as far as it was scrolled, in whole pages, so listing again drops nothing.
pub fn all_inboxes_count(listed: usize) -> usize {
    listed.next_multiple_of(PAGE).clamp(PAGE, ALL_INBOXES_MOST)
}

/// The unread threads in an account's inbox (All inboxes, the badge).
pub fn inbox_unread(client: &mail::Client) -> u32 {
    client
        .counts(&["INBOX".to_string()])
        .get("INBOX")
        .map_or(0, |(unread, _)| *unread)
}

/// A row of `account`'s, for a list that mixes accounts.
pub fn of_account<T: Listed>(summary: Summary, account: &str) -> T {
    let mut row = Row::from_summary(summary);
    row.account = Some(account.to_string());
    T::from(row)
}

/// One account's part of All inboxes: its newest `count` inbox threads, where its next
/// page starts, and its unread count. Blocking.
pub fn account_inbox<T: Listed>(
    client: &mail::Client,
    account: &str,
    count: usize,
) -> Result<AccountInbox<T>> {
    let (threads, next) = client.threads_page(View::Inbox, None, count, None)?;
    let unread = inbox_unread(client);
    let rows = threads
        .into_iter()
        .map(|summary| of_account(summary, account))
        .collect();
    Ok((rows, next, unread))
}

/// Every account's part put together (`all_inboxes`).
pub struct AllInboxes<T> {
    /// Newest first, each row marked with its account.
    pub rows: Vec<T>,
    /// Where each account's next page starts, by account id.
    pub pages: HashMap<String, String>,
    /// Each account's unread count, by account id.
    pub unread: HashMap<String, u32>,
    /// How many accounts could not be listed.
    pub failed: usize,
    /// The first of their errors.
    pub first_error: Option<anyhow::Error>,
}

/// Puts the accounts' parts of All inboxes together, newest first. An account that failed
/// is left out (and counted); all failing is for the caller to report.
pub fn all_inboxes<T: Listed>(results: Vec<(String, Result<AccountInbox<T>>)>) -> AllInboxes<T> {
    let mut all = AllInboxes {
        rows: Vec::new(),
        pages: HashMap::new(),
        unread: HashMap::new(),
        failed: 0,
        first_error: None,
    };
    for (id, result) in results {
        match result {
            Ok((rows, next, unread)) => {
                if let Some(next) = next {
                    all.pages.insert(id.clone(), next);
                }
                all.unread.insert(id, unread);
                all.rows.extend(rows);
            }
            Err(error) => {
                all.failed += 1;
                all.first_error.get_or_insert(error);
            }
        }
    }
    sort_newest_first(&mut all.rows);
    all
}

/// The next page of each account in All inboxes, put into `list` (newest first), without
/// the threads in `known` (by thread id and account: what is listed, cleared rows kept for
/// Undo too). `pages` holds where each account's next page starts and is moved on; an
/// answer for a page that is no longer the account's (a listing made meanwhile) is left
/// out. The first error, if any.
pub fn more_of_all_inboxes<T: Listed>(
    list: &mut Vec<T>,
    known: &std::collections::HashSet<(String, String)>,
    pages: &mut HashMap<String, String>,
    results: Vec<MoreOfAccount>,
) -> Option<anyhow::Error> {
    let mut first_error = None;
    for (id, page, result) in results {
        if pages.get(&id) != Some(&page) {
            continue;
        }
        match result {
            Ok((threads, next)) => {
                match next {
                    Some(next) => pages.insert(id.clone(), next),
                    None => pages.remove(&id),
                };
                list.extend(
                    threads
                        .into_iter()
                        .filter(|summary| !known.contains(&(summary.id.clone(), id.clone())))
                        .map(|summary| of_account(summary, &id)),
                );
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    sort_newest_first(list);
    first_error
}

/// How long what a check found stands, while nothing is seen to change.
const STANDS: std::time::Duration = std::time::Duration::from_secs(60);

/// When something was asked of the server, and how much had been seen to change by then:
/// our own writes and what the change feed brought.
#[derive(Clone, Copy)]
pub struct Asked {
    // Not an `Instant`, which stands still while the Mac sleeps.
    at: std::time::SystemTime,
    changes: u64,
}

impl Asked {
    pub fn now(changes: u64) -> Self {
        Self {
            at: std::time::SystemTime::now(),
            changes,
        }
    }

    /// Whether asking again now would be for nothing.
    pub fn stands(self, changes: u64) -> bool {
        self.changes == changes && self.at.elapsed().is_ok_and(|age| age < STANDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread(id: &str, snippet: &str) -> Row {
        Row {
            id: Some(id.into()),
            sender: "Ana".into(),
            subject: "Subject".into(),
            snippet: snippet.into(),
            ..Row::default()
        }
    }

    #[test]
    fn merge_keeps_downloaded_threads_and_refetches_changed_ones() {
        let mut same = thread("a", "hello");
        same.body = rich::from_text(vec!["Downloaded body".into()]).into();
        same.loaded = true;
        let mut changed = thread("b", "old reply");
        changed.body = rich::from_text(vec!["Stale body".into()]).into();
        changed.loaded = true;
        let cached = vec![same, changed];

        let merged = merge(
            &cached,
            vec![
                thread("c", "brand new"),
                thread("a", "hello"),
                thread("b", "new reply"),
            ],
        );

        // Order follows the fresh listing.
        let ids: Vec<_> = merged.iter().map(|m| m.id.clone().unwrap()).collect();
        assert_eq!(ids, ["c", "a", "b"]);
        // Unchanged thread keeps its body; new and changed ones will load again.
        assert!(merged[1].loaded);
        assert_eq!(merged[1].body[0].text, "Downloaded body");
        assert!(!merged[0].loaded && merged[0].body.is_empty());
        assert!(!merged[2].loaded && merged[2].body.is_empty());
    }

    #[test]
    fn merge_keeps_each_accounts_thread_apart() {
        let mut mine = thread("a", "hello");
        mine.body = rich::from_text(vec!["Mine".into()]).into();
        mine.loaded = true;
        let mut fresh_theirs = thread("a", "hello");
        fresh_theirs.account = Some("bbbbbbbbbbbb".into());
        let merged = merge(&[mine], vec![fresh_theirs, thread("a", "hello")]);
        assert!(
            !merged[0].loaded,
            "another account's thread with the same id"
        );
        assert_eq!(merged[1].body[0].text, "Mine");
    }

    #[test]
    fn a_copied_row_shares_its_messages_until_one_copy_changes_them() {
        let mut row = thread("a", "hello");
        row.body = rich::from_text(vec!["Body".into()]).into();
        let copy = row.clone();
        assert!(std::ptr::eq(row.body.as_ptr(), copy.body.as_ptr()));
        row.body[0].text = "Changed".into();
        assert_eq!(copy.body[0].text, "Body");
    }

    #[test]
    fn rows_stored_before_messages_were_shared_still_load() {
        let mut row = thread("a", "hello");
        row.body = rich::from_text(vec!["Body".into()]).into();
        let stored = serde_json::to_value(&row).unwrap();
        assert!(stored["body"].is_array(), "stored as the list itself");
        let back: Row = serde_json::from_value(stored).unwrap();
        assert_eq!(back.body[0].text, "Body");
    }

    #[test]
    fn rows_the_mac_kept_with_its_display_fields_still_load() {
        // As the macOS app wrote them before rows moved here: display fields beside the row.
        let stored = serde_json::json!({
            "id": "t1", "sender": "Ana", "initials": "A", "tone": "Mint", "subject": "Hi",
            "snippet": "hello", "time": "9:00", "thread": "2", "unread": true,
            "starred": false, "tag": null, "yesterday": false, "brief": "",
            "participants": "Ana, Ben · 2 messages",
            "earlier": [{"tone": "Rose", "initials": "B", "sender": "Ben", "snippet": "hi",
                         "when": "Mon", "blocks": [], "expanded": false}],
            "body": [], "rich": false, "loaded": true, "reply": null, "reply_all": [],
            "html": null, "timestamp_ms": 5
        });
        let row: Row = serde_json::from_value(stored).unwrap();
        assert_eq!(row.id.as_deref(), Some("t1"));
        assert_eq!(row.thread.as_deref(), Some("2"));
        assert_eq!(row.earlier[0].sender, "Ben");
        assert!(row.loaded && row.unread);
    }

    #[test]
    fn only_the_newest_are_kept_and_only_the_newest_with_their_text() {
        let rows: Vec<Row> = (0..KEEP_THREADS + 5)
            .map(|i| Row {
                loaded: true,
                body: rich::from_text(vec!["x".into()]).into(),
                ..thread(&i.to_string(), "s")
            })
            .collect();
        let kept = kept(&rows);
        assert_eq!(kept.len(), KEEP_THREADS);
        assert!(kept[KEEP_BODIES - 1].loaded);
        assert!(!kept[KEEP_BODIES].loaded && kept[KEEP_BODIES].body.is_empty());
    }

    #[test]
    fn records_are_named_by_mailbox_and_by_label_id() {
        assert_eq!(record(View::Inbox, None), "view-0");
        assert_eq!(record(View::Reminders, None), "view-15");
        assert_eq!(record(View::Label(3), Some("Label_7/x")), "label-Label_7x");
        assert_eq!(record(View::Label(3), None), "view-103");
    }

    fn summary(id: &str, labels: &[&str], at: i64) -> Summary {
        Summary {
            id: id.into(),
            sender: "Ana".into(),
            subject: "s".into(),
            snippet: "s".into(),
            timestamp_ms: at,
            message_count: 1,
            unread: false,
            starred: false,
            labels: labels.iter().map(|l| l.to_string()).collect(),
            message_labels: vec![labels.iter().map(|l| l.to_string()).collect()],
            senders: Vec::new(),
            people: Vec::new(),
        }
    }

    #[test]
    fn a_sync_moves_changed_threads_and_drops_those_that_left() {
        let mut list = vec![
            Row::from_summary(summary("a", &["INBOX"], 3)),
            Row::from_summary(summary("b", &["INBOX"], 2)),
        ];
        apply_updates(
            &mut list,
            vec![
                ("b".into(), Some(summary("b", &["INBOX"], 9))),
                ("a".into(), Some(summary("a", &[], 3))),
                ("c".into(), None),
            ],
            View::Inbox,
            None,
        );
        let ids: Vec<_> = list.iter().map(|r| r.id.clone().unwrap()).collect();
        assert_eq!(ids, ["b"]);
    }

    #[test]
    fn all_inboxes_merges_newest_first_and_counts_what_failed() {
        let all = all_inboxes::<Row>(vec![
            (
                "a".into(),
                Ok((
                    vec![of_account(summary("1", &["INBOX"], 5), "a")],
                    Some("next-a".into()),
                    2,
                )),
            ),
            ("b".into(), Err(anyhow::anyhow!("offline"))),
            (
                "c".into(),
                Ok((vec![of_account(summary("2", &["INBOX"], 9), "c")], None, 0)),
            ),
        ]);
        let order: Vec<_> = all
            .rows
            .iter()
            .map(|r| r.account.clone().unwrap())
            .collect();
        assert_eq!(order, ["c", "a"]);
        assert_eq!(all.failed, 1);
        assert_eq!(all.pages.get("a").map(String::as_str), Some("next-a"));
        assert_eq!(all.unread.get("a"), Some(&2));
        assert_eq!(all_inboxes_count(0), PAGE);
        assert_eq!(all_inboxes_count(31), 60);
        assert_eq!(all_inboxes_count(10_000), ALL_INBOXES_MOST);
    }

    #[test]
    fn a_next_page_of_all_inboxes_skips_what_is_listed_and_stale_pages() {
        let mut list: Vec<Row> = vec![of_account(summary("1", &["INBOX"], 9), "a")];
        let mut pages: HashMap<String, String> = [
            ("a".to_string(), "p1".to_string()),
            ("b".to_string(), "q1".to_string()),
        ]
        .into();
        let known = [("1".to_string(), "a".to_string())].into();
        let error = more_of_all_inboxes(
            &mut list,
            &known,
            &mut pages,
            vec![
                (
                    "a".into(),
                    "p1".into(),
                    Ok((vec![summary("1", &[], 9), summary("2", &[], 3)], None)),
                ),
                (
                    "b".into(),
                    "stale".into(),
                    Ok((vec![summary("x", &[], 1)], None)),
                ),
            ],
        );
        assert!(error.is_none());
        let ids: Vec<_> = list.iter().map(|r| r.id.clone().unwrap()).collect();
        assert_eq!(ids, ["1", "2"]);
        assert!(!pages.contains_key("a"));
        assert_eq!(pages.get("b").map(String::as_str), Some("q1"));
    }

    use crate::store::Store;
    use crate::testing::{EXPIRED, Fake};

    fn ids(rows: &[Row]) -> Vec<String> {
        rows.iter().map(|r| r.id.clone().unwrap()).collect()
    }

    #[test]
    fn a_kept_mailbox_is_listed_then_followed_from_the_change_feed() {
        let fake = Fake::new("me@example.com");
        fake.add(Fake::thread("a", &["INBOX"], 1));
        fake.add(Fake::thread("b", &["INBOX", "UNREAD"], 2));
        let client: Arc<mail::Client> = fake.clone();
        let store = Store::temp();

        let first = refresh(&*client, &store, View::Inbox, None).unwrap();
        assert!(first.relisted);
        assert_eq!(ids(&first.rows), ["b", "a"]);
        assert_eq!(ids(&stored(&store, View::Inbox, None)), ["b", "a"]);
        let meta: Meta = store.load(META).unwrap();
        assert_eq!(meta.account, "me@example.com");
        assert_eq!(meta.counts.get("INBOX"), Some(&(1, 2)));

        // A new thread, and one archived: only those are read again.
        fake.add(Fake::thread("c", &["INBOX"], 3));
        client.change("a", mail::Change::Archive).unwrap();
        *fake.changes.lock().unwrap() = mail::Changes {
            latest: "2".into(),
            threads: vec!["c".into(), "a".into()],
            new_unread_inbox: Vec::new(),
        };
        let second = refresh(&*client, &store, View::Inbox, None).unwrap();
        assert!(!second.relisted);
        assert_eq!(ids(&second.rows), ["c", "b"]);
        let meta: Meta = store.load(META).unwrap();
        assert_eq!(meta.synced_to.get("view-0").map(String::as_str), Some("2"));
    }

    #[test]
    fn a_feed_too_old_lists_again_and_keeps_what_was_downloaded() {
        let fake = Fake::new("me@example.com");
        fake.add(Fake::thread("a", &["INBOX"], 1));
        let client: Arc<mail::Client> = fake.clone();
        let store = Store::temp();
        refresh(&*client, &store, View::Inbox, None).unwrap();
        keep_thread(&store, "a", client.thread("a").unwrap()).unwrap();
        assert!(kept_thread(&store, "a").is_some_and(|row| row.body[0].text == "Body of a"));
        let mut meta: Meta = store.load(META).unwrap();
        meta.synced_to.insert("view-0".into(), EXPIRED.into());
        store.save(META, &meta).unwrap();
        let again = refresh(&*client, &store, View::Inbox, None).unwrap();
        assert!(again.relisted);
        assert!(
            again.rows[0].loaded,
            "the downloaded thread stays downloaded"
        );
    }

    #[test]
    fn a_store_kept_for_another_address_starts_clean() {
        let store = Store::temp();
        let before = Fake::new("old@example.com");
        before.add(Fake::thread("old", &["INBOX"], 1));
        let client: Arc<mail::Client> = before.clone();
        refresh(&*client, &store, View::Inbox, None).unwrap();
        refresh(&*client, &store, View::Sent, None).unwrap();
        let now = Fake::new("new@example.com");
        now.add(Fake::thread("new", &["INBOX"], 2));
        let client: Arc<mail::Client> = now.clone();
        let mut meta: Meta = store.load(META).unwrap();
        meta.synced_to.clear();
        store.save(META, &meta).unwrap();
        let listed = refresh(&*client, &store, View::Inbox, None).unwrap();
        assert_eq!(ids(&listed.rows), ["new"]);
        assert!(stored(&store, View::Sent, None).is_empty());
    }

    #[test]
    fn more_comes_after_what_is_kept() {
        let fake = Fake::new("me@example.com");
        for i in 0..(PAGE + 5) {
            fake.add(Fake::thread(&format!("t{i}"), &["INBOX"], i as i64));
        }
        let client: Arc<mail::Client> = fake.clone();
        let store = Store::temp();
        let first = refresh(&*client, &store, View::Inbox, None).unwrap();
        assert_eq!(first.rows.len(), PAGE);
        let (more_rows, next) = more(
            &*client,
            &store,
            View::Inbox,
            None,
            first.next_page.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(more_rows.len(), 5);
        assert!(next.is_none());
        assert_eq!(stored(&store, View::Inbox, None).len(), PAGE + 5);
    }

    fn label(id: &str, name: &str) -> Label {
        Label {
            id: id.into(),
            name: name.into(),
        }
    }

    #[test]
    fn a_label_made_or_renamed_elsewhere_is_a_change() {
        let here = [label("Label_1", "Blocked"), label("Label_2", "Later")];
        let reordered = [label("Label_2", "Later"), label("Label_1", "Blocked")];
        assert!(same_labels(&here, &reordered));
        let more = [
            label("Label_1", "Blocked"),
            label("Label_2", "Later"),
            label("Label_3", "Flights"),
        ];
        assert!(!same_labels(&here, &more));
        let renamed = [label("Label_1", "Blocked"), label("Label_2", "Soon")];
        assert!(!same_labels(&here, &renamed));
        assert!(!same_labels(&here, &here[..1]));
        assert_eq!(
            label_named(&here, " later ").map(|l| l.id.as_str()),
            Some("Label_2")
        );
    }

    #[test]
    fn what_was_found_stands_for_a_minute_or_until_a_change() {
        use std::time::{Duration, SystemTime};
        let asked = Asked::now(3);
        assert!(asked.stands(3) && !asked.stands(4));
        let aged = |seconds| Asked {
            at: SystemTime::now() - Duration::from_secs(seconds),
            changes: 3,
        };
        assert!(aged(50).stands(3) && !aged(61).stands(3));
        // The clock was set back.
        let ahead = Asked {
            at: SystemTime::now() + Duration::from_secs(600),
            changes: 3,
        };
        assert!(!ahead.stands(3));
    }
}
