//! The values Swift sees: plain records and enums, converted from the core's own types.
//! Ids (accounts, threads, messages, drafts, labels) are the engine's or the provider's,
//! and only ever handed back to the engine they came from.

use nimbra_core::{discover, listing, mail, rich, scheduled, servers, settings, snooze};

// ------------------------------------------------------------------ setup

/// The OAuth clients the app was built with. Passed in, never built into the engine.
/// `google_client_secret` is for a desktop client only: an iOS client has none.
#[derive(uniffi::Record)]
pub struct EngineConfig {
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub microsoft_client_id: Option<String>,
}

// ------------------------------------------------------------------ accounts

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AccountKind {
    Gmail,
    Microsoft,
    /// Its own IMAP and SMTP servers, with a password.
    Imap,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub kind: AccountKind,
    /// New messages are from it unless another is picked.
    pub is_default: bool,
}

/// A sign-in started in the browser: open `url` in `ASWebAuthenticationSession`, then
/// hand the address it came back to to the matching `finish_*_sign_in` with `id`.
#[derive(uniffi::Record)]
pub struct SignInRequest {
    pub id: String,
    pub url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ServerSecurity {
    Tls,
    StartTls,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MailServer {
    pub host: String,
    pub port: u16,
    pub security: ServerSecurity,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MailServers {
    /// The name to sign in with (often the address).
    pub username: String,
    pub imap: MailServer,
    pub smtp: MailServer,
}

/// What was found for an address.
#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum Discovery {
    Servers {
        servers: MailServers,
    },
    /// A Google account (gmail.com, or a domain whose mail Google runs). Continue with
    /// Google is the way in; `servers` are Gmail's, for adding it with an app password.
    Google {
        servers: MailServers,
    },
    /// The provider only lets mail apps in through its own sign-in: "Microsoft" or another
    /// name.
    NeedsOAuth {
        provider: String,
    },
    /// Nothing answered: the servers have to be typed in.
    Unknown,
}

// ------------------------------------------------------------------ mailboxes

/// Gmail's inbox categories, the Split Inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SplitCategory {
    Primary,
    Updates,
    Promotions,
    Social,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum Mailbox {
    Inbox,
    Split {
        category: SplitCategory,
    },
    Starred,
    Important,
    /// Put away until later (kept on the device, and Gmail's own snoozed threads).
    Snoozed,
    /// Put away until later unless someone replies (kept on the device).
    Reminders,
    Drafts,
    Sent,
    /// Archived ("Done"): everything not in the inbox, Sent, Drafts, Spam or Trash.
    Done,
    AllMail,
    Spam,
    Trash,
    /// One of the account's own labels (IMAP: a folder).
    Label {
        id: String,
    },
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct Label {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct LabelCount {
    pub label_id: String,
    pub unread: u32,
    pub total: u32,
}

/// One thread in a list: the row both apps keep (`listing::Row` in the engine).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ThreadRow {
    pub id: String,
    /// The account it is in, when the list mixes accounts (All inboxes).
    pub account_id: Option<String>,
    /// Who the row names: the latest message's sender, or in Sent and Drafts its first
    /// recipient.
    pub sender: String,
    /// The address of whoever `sender` names, for the avatar's tone and a quick reply
    /// before the thread is read. `None` when it has none that is an address, and for a
    /// row kept by 0.1.0 until its thread changes.
    pub sender_address: Option<String>,
    pub subject: String,
    pub snippet: String,
    pub timestamp_ms: i64,
    pub message_count: u32,
    pub unread: bool,
    pub starred: bool,
    /// Every label on any of its messages ("INBOX", "STARRED", label ids).
    pub labels: Vec<String>,
    /// Who wrote in it ("Ana, Ben · 3 messages"), once its messages are downloaded.
    pub participants: String,
    /// Its messages are on the device: `cached_thread` opens it at once, also offline.
    pub loaded: bool,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ThreadPage {
    /// `refresh_mailbox`: the whole list as kept, to show in place of the one shown.
    /// `load_more` and `search`: one page, to add after what is shown.
    pub threads: Vec<ThreadRow>,
    /// Where the page after these threads starts: hand it to `load_more` (or `search`);
    /// `None` at the end.
    pub next_page: Option<String>,
}

/// Where a mailbox goes in the list of mailboxes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MailboxSection {
    /// The Split Inbox (Gmail only).
    Split,
    Mailboxes,
    /// The account's labels (IMAP: its folders).
    Labels,
}

/// A mailbox an account lists, in order.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MailboxEntry {
    pub mailbox: Mailbox,
    pub section: MailboxSection,
    /// A label's name; `None` for the mailboxes every account has.
    pub name: Option<String>,
}

/// Every account's mailbox (All inboxes: every account's inbox), newest first.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct AllInboxesPage {
    pub threads: Vec<ThreadRow>,
    /// Each account's count of the mailbox, by account id: unread threads (every draft
    /// for Drafts).
    pub unread: Vec<LabelCount>,
    /// Accounts that could not be listed (left out). All of them failing is an error.
    pub failed_accounts: u32,
}

/// What changed since a sync point (`Engine::check_for_changes`).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct SyncResult {
    /// The point to sync from next time. Keep it with the mailbox.
    pub cursor: String,
    /// Threads with any change: fetch their rows again (`thread_summary`).
    pub changed_threads: Vec<String>,
    /// Threads that got a new unread message in the inbox, without those from blocked
    /// senders (which were put away).
    pub new_unread_inbox: Vec<String>,
    /// The first few of them, each its own notification (sender and subject).
    pub named: Vec<ThreadRow>,
    /// How many more arrived, summed up in one notification ("N more new messages").
    pub more_new: u32,
    /// Notifications are on in Preferences.
    pub notify: bool,
    /// The cursor given was too old: list the mailboxes afresh.
    pub expired: bool,
}

// ------------------------------------------------------------------ reading

#[derive(Clone, Debug, Default, PartialEq, uniffi::Record)]
pub struct Person {
    /// May be empty.
    pub name: String,
    pub address: String,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct AttachmentInfo {
    pub message_id: String,
    pub attachment_id: String,
    /// Already made safe to use as a file name.
    pub name: String,
    pub mime: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum BlockKind {
    Paragraph,
    Heading {
        level: u8,
    },
    ListItem {
        marker: String,
        depth: u8,
    },
    Code,
    Rule,
    /// A remote image: show it only when the user allows remote images.
    Image {
        src: String,
        alt: String,
    },
}

/// A styled run of a block's text. `start` and `end` are UTF-8 byte offsets into `text`.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct TextSpan {
    pub start: u32,
    pub end: u32,
    pub bold: bool,
    pub italic: bool,
    pub code: bool,
    /// Already limited to http, https and mailto.
    pub link: Option<String>,
}

/// A message's body as native blocks (the reader view), quoted history marked by depth.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct TextBlock {
    pub kind: BlockKind,
    pub quote_depth: u8,
    pub text: String,
    pub spans: Vec<TextSpan>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MailMessage {
    pub from: Person,
    pub to: Vec<Person>,
    pub cc: Vec<Person>,
    pub reply_to: Option<Person>,
    /// The sender's name as shown, and their bare address for replying.
    pub sender: String,
    pub address: String,
    /// Everyone else it was addressed to, for reply-all.
    pub others: Vec<String>,
    /// The RFC 5322 Message-ID, for threading a reply.
    pub message_id: String,
    pub timestamp_ms: i64,
    pub snippet: String,
    pub blocks: Vec<TextBlock>,
    /// The body as plain text (the blocks' text, a blank line between them).
    pub text: String,
    /// The original HTML, if it has one, for a locked-down web view.
    pub html: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
    /// Where to unsubscribe (`https:` or `mailto:`), from List-Unsubscribe.
    pub unsubscribe: Option<String>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MailThread {
    pub id: String,
    /// Oldest first.
    pub messages: Vec<MailMessage>,
}

// ------------------------------------------------------------------ actions

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ThreadAction {
    /// Archive.
    Done,
    /// Back into the inbox.
    MoveToInbox,
    Trash,
    Untrash,
    Star,
    Unstar,
    MarkRead,
    MarkUnread,
    Spam,
    NotSpam,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct SnoozedThread {
    pub thread_id: String,
    /// The account it is in, when it was snoozed from All inboxes as another's.
    pub account_id: Option<String>,
    /// When it comes back, or for a reminder, when it is checked for a reply.
    pub until_ms: i64,
    /// A reminder: it comes back only if nobody replied.
    pub only_if_no_reply: bool,
    pub subject: String,
    pub sender: String,
    pub snippet: String,
}

// ------------------------------------------------------------------ writing

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ReplyRef {
    pub thread_id: String,
    /// Message-ID of the message being answered.
    pub message_id: String,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct OutgoingFile {
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// A message the user wrote. Addresses are comma separated, as typed.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct OutgoingMessage {
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    pub body: String,
    /// The same message as HTML, when it was written with formatting.
    pub html: Option<String>,
    pub files: Vec<OutgoingFile>,
    /// Attachments already on the draft being edited.
    pub kept: Vec<AttachmentInfo>,
    pub reply: Option<ReplyRef>,
}

/// How a wait for changes ended (`ChangeWatch::wait`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WatchOutcome {
    Changed,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AnswerKind {
    Reply,
    ReplyAll,
    Forward,
}

/// What a reply or forward starts with (`Engine::start_answer`).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct DraftStart {
    pub subject: String,
    pub to: Vec<String>,
    /// The earlier message as text, folded under what is written; added when sent
    /// (`message_html`).
    pub quoted: Option<String>,
    /// The files a forward carries.
    pub kept: Vec<AttachmentInfo>,
    pub reply: Option<ReplyRef>,
    /// The account's default signature, shown under what is written.
    pub signature: Option<SignatureInfo>,
}

/// A draft's HTML taken apart (`split_draft_html`).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct DraftParts {
    pub written: String,
    pub signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct DraftMessage {
    pub id: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    /// What the user wrote, signature included.
    pub body: String,
    /// The earlier message it quotes or forwards.
    pub quoted: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
    pub reply: Option<ReplyRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SendStage {
    /// Has not left the device: it can still be taken back.
    Held,
    /// A request is out.
    Out,
    /// The answer never came: it may or may not have been sent. Check Sent.
    Unsure,
    /// The server said no.
    Refused,
    /// Sent, taken back, or saved to Drafts.
    Over,
}

/// What became of an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ActionOutcome {
    Done,
    /// Offline: it waits on the device and is made once the server can be reached.
    Queued,
}

/// What became of a message handed to the server (`OutgoingSend::deliver`).
#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum SendOutcome {
    Sent,
    /// Offline: it stays held. Hand it to `Engine::wait_for_connection`; `catch_up` sends it.
    WaitingForConnection,
    /// The answer never came: it may have gone. Never sent again by itself.
    MaybeSent {
        in_drafts: bool,
    },
    /// The server said no.
    Refused {
        message: String,
    },
    /// The account's sign-in is gone: sign in again.
    SignedOut,
    /// It was not waiting to be sent (sent already, or taken back).
    NotWaiting,
}

/// Why a message went to Drafts instead of out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LeftBehind {
    /// It may already have been sent: check Sent before sending it again.
    MaybeSent,
    /// It was not sent.
    Refused,
    /// It was still being written when the app quit.
    Writing,
    /// It was to be sent later, and that was not kept before the app quit.
    Unscheduled,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MovedToDrafts {
    pub subject: String,
    pub why: LeftBehind,
    /// Drafts has it; `false`: it is still kept on the device, to try again.
    pub in_drafts: bool,
}

/// What an earlier run left unsent (`Engine::unsent`).
#[derive(uniffi::Record)]
pub struct UnsentReport {
    /// Never left: send these (`deliver`).
    pub to_send: Vec<std::sync::Arc<crate::sending::OutgoingSend>>,
    pub moved_to_drafts: Vec<MovedToDrafts>,
}

/// What a catch-up got done (`Engine::catch_up`).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct CatchUpResult {
    pub changes: u32,
    pub sent: u32,
    pub moved_to_drafts: Vec<MovedToDrafts>,
    /// Nothing waits any more: back online.
    pub done: bool,
}

/// What waits for an account, and when to look again (`Engine::pending_work`).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PendingWork {
    pub queued_changes: u32,
    pub waiting_messages: u32,
    /// The soonest snooze, send later or retry (ms since 1970); `None`: nothing is due.
    pub next_deadline_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SendLaterKind {
    InAnHour,
    ThisEvening,
    TomorrowMorning,
    MondayMorning,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct SendLaterTime {
    pub kind: SendLaterKind,
    pub at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ScheduledSend {
    pub draft_id: String,
    pub at_ms: i64,
    pub subject: String,
}

// ------------------------------------------------------------------ preferences

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct SignatureInfo {
    pub id: String,
    pub account_id: String,
    pub name: String,
    /// Already cleaned: safe to show and send.
    pub html: String,
    pub is_default: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MarkReadChoice {
    /// As soon as it is opened.
    Open,
    /// After it has been open for two seconds.
    Delay,
    /// Only with Mark as read.
    Never,
}

/// The preferences both apps share. The rest of the settings file is the Mac's.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct Preferences {
    pub notifications: bool,
    /// Open mail in its original formatting (the web view) rather than the reader.
    pub original_view: bool,
    /// Show remote images in the original view.
    pub load_images: bool,
    /// In dark mode, give light emails a dark page.
    pub dark_emails: bool,
    pub mark_read: MarkReadChoice,
    /// How often to check for new mail, in seconds.
    pub check_every_seconds: u32,
    /// How long a sent message can still be taken back, in seconds (0: sent at once).
    pub undo_send_seconds: u32,
    /// Quote the message being answered in a reply.
    pub quote_replies: bool,
    /// Unread mail counts on the app icon.
    pub badge: bool,
    /// New mail notifications play a sound.
    pub notification_sound: bool,
}

// ------------------------------------------------------------------ conversions

impl From<&servers::Server> for MailServer {
    fn from(server: &servers::Server) -> Self {
        MailServer {
            host: server.host.clone(),
            port: server.port,
            security: match server.security {
                servers::Security::Tls => ServerSecurity::Tls,
                servers::Security::StartTls => ServerSecurity::StartTls,
            },
        }
    }
}

impl From<&MailServer> for servers::Server {
    fn from(server: &MailServer) -> Self {
        servers::Server::new(
            &server.host,
            server.port,
            match server.security {
                ServerSecurity::Tls => servers::Security::Tls,
                ServerSecurity::StartTls => servers::Security::StartTls,
            },
        )
    }
}

impl From<&servers::Servers> for MailServers {
    fn from(servers: &servers::Servers) -> Self {
        MailServers {
            username: servers.username.clone(),
            imap: (&servers.imap).into(),
            smtp: (&servers.smtp).into(),
        }
    }
}

impl From<&MailServers> for servers::Servers {
    fn from(servers: &MailServers) -> Self {
        servers::Servers {
            username: servers.username.trim().to_string(),
            imap: (&servers.imap).into(),
            smtp: (&servers.smtp).into(),
        }
    }
}

impl From<discover::Found> for Discovery {
    fn from(found: discover::Found) -> Self {
        match found {
            discover::Found::Servers(servers) => Discovery::Servers {
                servers: (&servers).into(),
            },
            discover::Found::Google(servers) => Discovery::Google {
                servers: (&servers).into(),
            },
            discover::Found::NeedsOAuth { provider } => Discovery::NeedsOAuth {
                provider: provider.to_string(),
            },
            discover::Found::Unknown => Discovery::Unknown,
        }
    }
}

impl Mailbox {
    /// The mailbox for one of the core's (not a search, nor All inboxes).
    pub(crate) fn of_view(view: mail::View) -> Option<Mailbox> {
        Some(match view {
            mail::View::Inbox => Mailbox::Inbox,
            mail::View::Primary => Mailbox::Split {
                category: SplitCategory::Primary,
            },
            mail::View::Updates => Mailbox::Split {
                category: SplitCategory::Updates,
            },
            mail::View::Promotions => Mailbox::Split {
                category: SplitCategory::Promotions,
            },
            mail::View::Social => Mailbox::Split {
                category: SplitCategory::Social,
            },
            mail::View::Starred => Mailbox::Starred,
            mail::View::Important => Mailbox::Important,
            mail::View::Snoozed => Mailbox::Snoozed,
            mail::View::Reminders => Mailbox::Reminders,
            mail::View::Drafts => Mailbox::Drafts,
            mail::View::Sent => Mailbox::Sent,
            mail::View::Done => Mailbox::Done,
            mail::View::AllMail => Mailbox::AllMail,
            mail::View::Spam => Mailbox::Spam,
            mail::View::Trash => Mailbox::Trash,
            mail::View::Every(_) | mail::View::Search | mail::View::Label(_) => return None,
        })
    }

    /// The core's mailbox and the label (or folder) id it needs.
    pub(crate) fn view(&self) -> (mail::View, Option<&str>) {
        match self {
            Mailbox::Inbox => (mail::View::Inbox, None),
            Mailbox::Split { category } => (
                match category {
                    SplitCategory::Primary => mail::View::Primary,
                    SplitCategory::Updates => mail::View::Updates,
                    SplitCategory::Promotions => mail::View::Promotions,
                    SplitCategory::Social => mail::View::Social,
                },
                None,
            ),
            Mailbox::Starred => (mail::View::Starred, None),
            Mailbox::Snoozed => (mail::View::Snoozed, None),
            Mailbox::Reminders => (mail::View::Reminders, None),
            Mailbox::Important => (mail::View::Important, None),
            Mailbox::Drafts => (mail::View::Drafts, None),
            Mailbox::Sent => (mail::View::Sent, None),
            Mailbox::Done => (mail::View::Done, None),
            Mailbox::AllMail => (mail::View::AllMail, None),
            Mailbox::Spam => (mail::View::Spam, None),
            Mailbox::Trash => (mail::View::Trash, None),
            // The position is not used when the id is given.
            Mailbox::Label { id } => (mail::View::Label(0), Some(id.as_str())),
        }
    }
}

impl From<&mail::Summary> for ThreadRow {
    fn from(summary: &mail::Summary) -> Self {
        (&listing::Row::from_summary(summary.clone())).into()
    }
}

impl From<&listing::Row> for ThreadRow {
    fn from(row: &listing::Row) -> Self {
        ThreadRow {
            id: row.id.clone().unwrap_or_default(),
            account_id: row.account.clone(),
            sender: row.sender.clone(),
            sender_address: Some(row.sender_address.trim())
                .filter(|address| mail::is_address(address))
                .map(String::from),
            subject: row.subject.clone(),
            snippet: row.snippet.clone(),
            timestamp_ms: row.timestamp_ms,
            message_count: row
                .thread
                .as_deref()
                .and_then(|count| count.parse().ok())
                .unwrap_or(1),
            unread: row.unread,
            starred: row.starred,
            labels: row.labels.clone(),
            participants: row.participants.clone(),
            loaded: row.loaded,
        }
    }
}

impl MailMessage {
    fn kept(header: &listing::Header, sender: &str, snippet: &str, blocks: &[rich::Block]) -> Self {
        MailMessage {
            from: (&header.from).into(),
            to: header.to.iter().map(Person::from).collect(),
            cc: header.cc.iter().map(Person::from).collect(),
            reply_to: header.reply_to.as_ref().map(Person::from),
            sender: sender.to_string(),
            address: header.from.address.clone(),
            others: header.everyone(),
            message_id: header.message_id.clone(),
            timestamp_ms: header.date_ms,
            snippet: snippet.to_string(),
            blocks: blocks.iter().map(TextBlock::from).collect(),
            text: plain_text(blocks),
            html: None,
            attachments: header
                .attachments
                .iter()
                .map(AttachmentInfo::from)
                .collect(),
            unsubscribe: header.unsubscribe.clone(),
        }
    }
}

impl From<&listing::Row> for MailThread {
    /// A thread as kept with its row: the earlier messages, then the latest.
    fn from(row: &listing::Row) -> Self {
        let mut messages: Vec<MailMessage> = row
            .earlier
            .iter()
            .rev()
            .map(|e| {
                let mut message = MailMessage::kept(&e.header, &e.sender, &e.snippet, &e.blocks);
                message.html = e.html.clone();
                message
            })
            .collect();
        let sender = row.header.from.label().to_string();
        let mut latest = MailMessage::kept(&row.header, &sender, &row.snippet, &row.body);
        latest.html = row.html.clone();
        if !row.reply_all.is_empty() {
            latest.others = row.reply_all.clone();
        }
        messages.push(latest);
        MailThread {
            id: row.id.clone().unwrap_or_default(),
            messages,
        }
    }
}

impl From<mail::Label> for Label {
    fn from(label: mail::Label) -> Self {
        Label {
            id: label.id,
            name: label.name,
        }
    }
}

impl From<&mail::Person> for Person {
    fn from(person: &mail::Person) -> Self {
        Person {
            name: person.name.clone(),
            address: person.address.clone(),
        }
    }
}

impl From<&mail::Attachment> for AttachmentInfo {
    fn from(attachment: &mail::Attachment) -> Self {
        AttachmentInfo {
            message_id: attachment.message_id.clone(),
            attachment_id: attachment.attachment_id.clone(),
            name: mail::safe_file_name(&attachment.name),
            mime: attachment.mime.clone(),
            size: attachment.size,
        }
    }
}

impl From<&AttachmentInfo> for mail::Attachment {
    fn from(attachment: &AttachmentInfo) -> Self {
        mail::Attachment {
            message_id: attachment.message_id.clone(),
            attachment_id: attachment.attachment_id.clone(),
            name: attachment.name.clone(),
            mime: attachment.mime.clone(),
            size: attachment.size,
        }
    }
}

impl From<&rich::Block> for TextBlock {
    fn from(block: &rich::Block) -> Self {
        let offset = |at: usize| u32::try_from(at.min(block.text.len())).unwrap_or(u32::MAX);
        TextBlock {
            kind: match &block.kind {
                rich::Kind::Paragraph => BlockKind::Paragraph,
                rich::Kind::Heading(level) => BlockKind::Heading { level: *level },
                rich::Kind::Item { marker, depth } => BlockKind::ListItem {
                    marker: marker.clone(),
                    depth: *depth,
                },
                rich::Kind::Code => BlockKind::Code,
                rich::Kind::Rule => BlockKind::Rule,
                rich::Kind::Image { src, alt } => BlockKind::Image {
                    src: src.clone(),
                    alt: alt.clone(),
                },
            },
            quote_depth: block.quote,
            text: block.text.clone(),
            spans: block
                .spans
                .iter()
                .map(|span| TextSpan {
                    start: offset(span.range.start),
                    end: offset(span.range.end),
                    bold: span.bold,
                    italic: span.italic,
                    code: span.code,
                    link: span.link.clone(),
                })
                .collect(),
        }
    }
}

/// The blocks' text, a blank line between them.
pub(crate) fn plain_text(blocks: &[rich::Block]) -> String {
    blocks
        .iter()
        .filter(|block| !block.text.is_empty())
        .map(|block| block.text.as_str())
        .collect::<Vec<_>>()
        .join("\n\n")
}

impl From<&mail::Message> for MailMessage {
    fn from(message: &mail::Message) -> Self {
        MailMessage {
            from: (&message.from).into(),
            to: message.to.iter().map(Person::from).collect(),
            cc: message.cc.iter().map(Person::from).collect(),
            reply_to: message.reply_to.as_ref().map(Person::from),
            sender: message.sender.clone(),
            address: message.address.clone(),
            others: message.others.clone(),
            message_id: message.message_id.clone(),
            timestamp_ms: message.timestamp_ms,
            snippet: message.snippet.clone(),
            blocks: message.blocks.iter().map(TextBlock::from).collect(),
            text: plain_text(&message.blocks),
            html: message.html.clone(),
            attachments: message
                .attachments
                .iter()
                .map(AttachmentInfo::from)
                .collect(),
            unsubscribe: message.unsubscribe.clone(),
        }
    }
}

impl ThreadAction {
    pub(crate) fn change(self) -> mail::Change {
        match self {
            ThreadAction::Done => mail::Change::Archive,
            ThreadAction::MoveToInbox => mail::Change::Unarchive,
            ThreadAction::Trash => mail::Change::Trash,
            ThreadAction::Untrash => mail::Change::Untrash,
            ThreadAction::Star => mail::Change::Star,
            ThreadAction::Unstar => mail::Change::Unstar,
            ThreadAction::MarkRead => mail::Change::MarkRead,
            ThreadAction::MarkUnread => mail::Change::MarkUnread,
            ThreadAction::Spam => mail::Change::Spam,
            ThreadAction::NotSpam => mail::Change::NotSpam,
        }
    }

    pub(crate) fn from_change(change: mail::Change) -> Self {
        match change {
            mail::Change::Archive => ThreadAction::Done,
            mail::Change::Unarchive => ThreadAction::MoveToInbox,
            mail::Change::Trash => ThreadAction::Trash,
            mail::Change::Untrash => ThreadAction::Untrash,
            mail::Change::Star => ThreadAction::Star,
            mail::Change::Unstar => ThreadAction::Unstar,
            mail::Change::MarkRead => ThreadAction::MarkRead,
            mail::Change::MarkUnread => ThreadAction::MarkUnread,
            mail::Change::Spam => ThreadAction::Spam,
            mail::Change::NotSpam => ThreadAction::NotSpam,
        }
    }
}

impl From<&snooze::Snooze> for SnoozedThread {
    fn from(item: &snooze::Snooze) -> Self {
        SnoozedThread {
            thread_id: item.thread_id.clone(),
            account_id: item.mail.account.clone(),
            until_ms: item.until_ms,
            only_if_no_reply: item.no_reply,
            subject: item.mail.subject.clone(),
            sender: item.mail.sender.clone(),
            snippet: item.mail.snippet.clone(),
        }
    }
}

/// A time the Snooze menu offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SnoozeKind {
    LaterToday,
    InThreeHours,
    Tomorrow,
    TomorrowEvening,
    ThisWeekend,
    NextWeek,
    /// A reminder in three days, if nobody replied.
    NoReplyInThreeDays,
    /// A reminder in a week, if nobody replied.
    NoReplyInAWeek,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct SnoozeTime {
    pub kind: SnoozeKind,
    pub until_ms: i64,
    pub only_if_no_reply: bool,
}

/// A time of day, as typed (`parse_time`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TimeOfDay {
    pub hour: u32,
    pub minute: u32,
}

impl From<&OutgoingMessage> for mail::Outgoing {
    fn from(message: &OutgoingMessage) -> Self {
        mail::Outgoing {
            to: message.to.clone(),
            cc: message.cc.clone(),
            bcc: message.bcc.clone(),
            subject: message.subject.clone(),
            body: message.body.clone(),
            html: message.html.clone(),
            files: message
                .files
                .iter()
                .map(|file| mail::OutgoingFile {
                    name: mail::safe_file_name(&file.name),
                    mime: file.mime.clone(),
                    bytes: file.bytes.clone(),
                })
                .collect(),
            kept: message.kept.iter().map(mail::Attachment::from).collect(),
            reply: message.reply.as_ref().map(|reply| mail::ReplyTo {
                thread_id: reply.thread_id.clone(),
                message_id: reply.message_id.clone(),
            }),
        }
    }
}

impl From<&mail::Outgoing> for OutgoingMessage {
    fn from(message: &mail::Outgoing) -> Self {
        OutgoingMessage {
            to: message.to.clone(),
            cc: message.cc.clone(),
            bcc: message.bcc.clone(),
            subject: message.subject.clone(),
            body: message.body.clone(),
            html: message.html.clone(),
            files: message
                .files
                .iter()
                .map(|file| OutgoingFile {
                    name: file.name.clone(),
                    mime: file.mime.clone(),
                    bytes: file.bytes.clone(),
                })
                .collect(),
            kept: message.kept.iter().map(AttachmentInfo::from).collect(),
            reply: message.reply.as_ref().map(|reply| ReplyRef {
                thread_id: reply.thread_id.clone(),
                message_id: reply.message_id.clone(),
            }),
        }
    }
}

impl From<mail::Draft> for DraftMessage {
    fn from(draft: mail::Draft) -> Self {
        DraftMessage {
            id: draft.id,
            to: draft.to,
            cc: draft.cc,
            bcc: draft.bcc,
            subject: draft.subject,
            body: draft.body,
            quoted: draft.quoted,
            html: draft.html,
            attachments: draft.attachments.iter().map(AttachmentInfo::from).collect(),
            reply: draft.reply.map(|reply| ReplyRef {
                thread_id: reply.thread_id,
                message_id: reply.message_id,
            }),
        }
    }
}

impl From<nimbra_core::sending::Stage> for SendStage {
    fn from(stage: nimbra_core::sending::Stage) -> Self {
        use nimbra_core::sending::Stage;
        match stage {
            Stage::Held => SendStage::Held,
            Stage::Out => SendStage::Out,
            Stage::Unsure => SendStage::Unsure,
            Stage::Refused => SendStage::Refused,
            // The others are the Mac's quitting states: nothing to send from here.
            Stage::Writing | Stage::Unscheduled | Stage::Discarded | Stage::Over => SendStage::Over,
        }
    }
}

impl From<&scheduled::Scheduled> for ScheduledSend {
    fn from(item: &scheduled::Scheduled) -> Self {
        ScheduledSend {
            draft_id: item.draft_id.clone(),
            at_ms: item.at_ms,
            subject: item.subject.clone(),
        }
    }
}

impl From<settings::MarkRead> for MarkReadChoice {
    fn from(choice: settings::MarkRead) -> Self {
        match choice {
            settings::MarkRead::Open => MarkReadChoice::Open,
            settings::MarkRead::Delay => MarkReadChoice::Delay,
            settings::MarkRead::Never => MarkReadChoice::Never,
        }
    }
}

impl From<MarkReadChoice> for settings::MarkRead {
    fn from(choice: MarkReadChoice) -> Self {
        match choice {
            MarkReadChoice::Open => settings::MarkRead::Open,
            MarkReadChoice::Delay => settings::MarkRead::Delay,
            MarkReadChoice::Never => settings::MarkRead::Never,
        }
    }
}
