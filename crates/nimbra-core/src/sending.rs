//! A message from Send until Gmail has it. It is kept in its account's store meanwhile, so
//! that quitting or switching accounts cannot lose it, and one that may already have gone
//! out is never sent again by itself. What was being written at quit is kept the same way,
//! for Drafts only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::mail;
use crate::store::Store;

const RECORD: &str = "sending-";

#[derive(Clone, Serialize, Deserialize)]
pub struct QueuedMail {
    pub draft_id: Option<String>,
    pub outgoing: mail::Outgoing,
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum Stage {
    /// Has not left this Mac: safe to send.
    Held,
    /// A request is out. Found like this at launch, it may or may not have been sent.
    Out,
    /// A request was out and its answer never came: it may or may not have been sent.
    Unsure,
    /// Gmail said no.
    Refused,
    /// Was still being written at quit: for Drafts, never to be sent.
    Writing,
    /// The same, with a time to send it that was not saved yet.
    Unscheduled,
    /// Discarded at quit: its draft is to be deleted, and nothing sent or saved.
    Discarded,
    /// Sent, taken back, or handed on.
    Over,
}

#[derive(Serialize, Deserialize)]
struct Record {
    stage: Stage,
    mail: QueuedMail,
}

/// A `Record` as it is written, from what a job holds.
#[derive(Serialize)]
struct Written<'a> {
    stage: Stage,
    mail: WrittenMail<'a>,
}

#[derive(Serialize)]
struct WrittenMail<'a> {
    draft_id: &'a Option<String>,
    outgoing: &'a mail::Outgoing,
}

struct State {
    stage: Stage,
    draft_id: Option<String>,
    /// Shared with a write under way, so that taking a copy to write is no work.
    outgoing: Arc<mail::Outgoing>,
    store: Option<Arc<Store>>,
    /// Held for as long as this copy of Nimbra looks after the message, so that another
    /// does not send it as left behind. The system lets go of it however the app ends.
    claim: Option<std::fs::File>,
}

impl State {
    fn new(stage: Stage, mail: QueuedMail, store: Option<Arc<Store>>) -> Self {
        State {
            stage,
            draft_id: mail.draft_id,
            outgoing: Arc::new(mail.outgoing),
            store,
            claim: None,
        }
    }
}

pub struct Job {
    pub account: String,
    /// The composer it came from; none for one found at launch.
    pub composer: Option<u64>,
    client: Arc<mail::Client>,
    name: String,
    /// It is on disk.
    kept: AtomicBool,
    /// Held only for moments, never while writing or asking the keychain: the main thread
    /// takes it (Undo, the subject for a notice).
    state: Mutex<State>,
    changed: Condvar,
    /// One write at a time, in order, outside `state`.
    writing: Mutex<()>,
}

impl Job {
    /// `store` is the account's when that is open; otherwise `keep` opens it.
    pub fn new(
        account: String,
        composer: u64,
        client: Arc<mail::Client>,
        store: Option<Arc<Store>>,
        mail: QueuedMail,
    ) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            account,
            composer: Some(composer),
            client,
            name: format!("{RECORD}{}", mail::random_hex(8)?),
            kept: AtomicBool::new(false),
            state: Mutex::new(State::new(Stage::Held, mail, store)),
            changed: Condvar::new(),
            writing: Mutex::new(()),
        }))
    }

    /// One that was still open at quit: `stage` is `Writing`, `Unscheduled` or `Discarded`.
    pub fn unfinished(
        account: String,
        composer: u64,
        client: Arc<mail::Client>,
        store: Option<Arc<Store>>,
        mail: QueuedMail,
        stage: Stage,
    ) -> anyhow::Result<Arc<Self>> {
        let job = Job::new(account, composer, client, store, mail)?;
        job.state().stage = stage;
        Ok(job)
    }

    /// One from the offline queue of earlier versions.
    pub fn queued(
        account: &str,
        client: &Arc<mail::Client>,
        store: &Arc<Store>,
        mail: QueuedMail,
    ) -> anyhow::Result<Arc<Self>> {
        Job::new(
            account.to_string(),
            0,
            client.clone(),
            Some(store.clone()),
            mail,
        )
    }

    /// What an earlier run, or a switch of accounts, left in this account's store.
    /// Blocking.
    pub fn left_behind(
        account: &str,
        client: &Arc<mail::Client>,
        store: &Arc<Store>,
    ) -> Vec<Arc<Self>> {
        let mut found = Vec::new();
        for name in store.names(RECORD) {
            let Some(claim) = store.claim(&name) else {
                continue; // being looked after
            };
            let Some(record) = store.load::<Record>(&name) else {
                continue;
            };
            let mut state = State::new(record.stage, record.mail, Some(store.clone()));
            state.claim = Some(claim);
            found.push(Arc::new(Self {
                account: account.to_string(),
                composer: None,
                client: client.clone(),
                name,
                kept: AtomicBool::new(true),
                state: Mutex::new(state),
                changed: Condvar::new(),
                writing: Mutex::new(()),
            }));
        }
        found
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn stage(&self) -> Stage {
        self.state().stage
    }

    pub fn subject(&self) -> String {
        self.state().outgoing.subject.clone()
    }

    /// Its draft (when saved) and the message, as it is now.
    pub fn mail(&self) -> (Option<String>, Arc<mail::Outgoing>) {
        let state = self.state();
        (state.draft_id.clone(), state.outgoing.clone())
    }

    /// Writes it down; whether that worked. Blocking.
    pub fn keep(&self) -> bool {
        self.write()
    }

    /// The same on Send, which is worth asking the keychain again for. Blocking.
    pub fn keep_asking(&self) -> bool {
        if Store::unreadable(&self.account)
            && let Ok(store) = Store::open(&self.account)
        {
            self.state().store.get_or_insert(Arc::new(store));
        }
        self.keep()
    }

    /// Whether it is on disk.
    pub fn kept(&self) -> bool {
        self.kept.load(Ordering::Relaxed)
    }

    fn write(&self) -> bool {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let store = self.state().store.clone();
        let store = match store {
            Some(store) => store,
            None => match Store::open_quietly(&self.account) {
                Ok(store) => self.state().store.get_or_insert(Arc::new(store)).clone(),
                Err(_) => return false,
            },
        };
        let (stage, draft_id, outgoing) = {
            let mut state = self.state();
            if state.stage == Stage::Over {
                return false;
            }
            if state.claim.is_none() {
                state.claim = store.claim(&self.name);
            }
            (state.stage, state.draft_id.clone(), state.outgoing.clone())
        };
        let written = Written {
            stage,
            mail: WrittenMail {
                draft_id: &draft_id,
                outgoing: &outgoing,
            },
        };
        let saved = store.save(&self.name, &written).is_ok();
        // Taken back while it was written: what was just written goes too. Here or in
        // `forget`, whichever is last, as both look under the lock.
        let state = self.state();
        if state.stage == Stage::Over {
            store.remove(&self.name);
            return false;
        }
        self.kept.store(saved, Ordering::Relaxed);
        if !saved {
            eprintln!("nimbra: could not save the message being sent");
        }
        saved
    }

    /// Taken back or handed on: nothing is left of it on disk. This does not wait for a
    /// write under way (that removes what it wrote itself), nor for a background thread,
    /// as quitting straight after Undo must not send it.
    pub fn forget(&self) {
        let store = {
            let mut state = self.state();
            state.stage = Stage::Over;
            state.store.clone()
        };
        if let Some(store) = store {
            store.remove(&self.name);
        }
        self.changed.notify_all();
    }

    /// The draft saved since Send, which sending then uses up.
    pub fn set_draft(&self, draft_id: Option<String>) {
        if draft_id.is_some() {
            self.state().draft_id = draft_id;
        }
    }

    /// Sends it, once however often it is called: `None` if it was not waiting. Blocking.
    pub fn send(&self) -> Option<anyhow::Result<()>> {
        {
            let mut state = self.state();
            if state.stage != Stage::Held {
                return None;
            }
            state.stage = Stage::Out;
        }
        // On disk as possibly sent before the request leaves.
        self.write();
        let (draft_id, outgoing) = self.mail();
        let result = match &draft_id {
            Some(id) => self.client.send_draft(id, &outgoing),
            None => self.client.send_message(&outgoing),
        };
        let mut state = self.state();
        if state.stage == Stage::Out {
            state.stage = match &result {
                Ok(()) => Stage::Over,
                Err(error) if error.is::<mail::MayHaveArrived>() => Stage::Unsure,
                Err(error) if error.is::<mail::Offline>() => Stage::Held,
                Err(_) => Stage::Refused,
            };
            if state.stage == Stage::Over {
                if let Some(store) = &state.store {
                    store.remove(&self.name);
                }
            } else {
                drop(state);
                self.write();
                state = self.state();
            }
        }
        drop(state);
        self.changed.notify_all();
        Some(result)
    }

    /// Puts it in Gmail's Drafts. Until that works it stays on disk. Blocking.
    pub fn to_drafts(&self) -> bool {
        self.saved_as_draft().is_some()
    }

    /// The same, for who needs the draft's id.
    pub fn saved_as_draft(&self) -> Option<String> {
        let (draft_id, outgoing) = self.mail();
        let id = self
            .client
            .keep_as_draft(draft_id.as_deref(), &outgoing)
            .ok()?;
        self.forget();
        Some(id)
    }

    /// Deletes what was saved of a discarded message. Until that works it stays on disk.
    /// Blocking.
    pub fn discard(&self) -> bool {
        let deleted = match self.mail().0 {
            None => true,
            Some(id) => match self.client.delete_draft(&id) {
                Ok(()) => true,
                Err(error) => mail::is_gone(&error),
            },
        };
        if deleted {
            self.forget();
        }
        deleted
    }

    fn wait(&self) {
        let state = self.state();
        drop(
            self.changed
                .wait_while(state, |state| state.stage == Stage::Out)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
}

/// Quitting: sends what is waiting and waits for what is out, until `deadline`. Whatever is
/// not through by then is on disk for the next launch.
pub fn finish(jobs: &[Arc<Job>], deadline: Instant) {
    let (done, finished) = mpsc::channel();
    for job in jobs {
        let (job, done) = (job.clone(), done.clone());
        std::thread::spawn(move || {
            // It may already be out, on another thread.
            if job.send().is_none() {
                job.wait();
            }
            done.send(()).ok();
        });
    }
    for _ in jobs {
        let left = deadline.saturating_duration_since(Instant::now());
        if finished.recv_timeout(left).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Arc<mail::Client> {
        let server =
            |port| crate::servers::Server::new("localhost", port, crate::servers::Security::Tls);
        Arc::new(crate::imap_mail::Client::new(
            String::new(),
            String::new(),
            crate::servers::Servers {
                username: "me".into(),
                imap: server(1),
                smtp: server(1),
            },
            crate::imap_mail::Credential::Password(String::new()),
        ))
    }

    fn with_file(bytes: Vec<u8>) -> QueuedMail {
        QueuedMail {
            draft_id: None,
            outgoing: mail::Outgoing {
                subject: "Report".into(),
                files: vec![mail::OutgoingFile {
                    name: "a.bin".into(),
                    mime: "application/octet-stream".into(),
                    bytes,
                }],
                ..mail::Outgoing::default()
            },
        }
    }

    #[test]
    fn taking_back_does_not_wait_for_a_write_and_leaves_nothing_on_disk() {
        let (store, release) = Store::temp_held();
        let job = Job::new(
            String::new(),
            1,
            client(),
            Some(store.clone()),
            with_file(vec![1; 64]),
        )
        .unwrap();
        // Its record is busy on the writer, so a write of it waits.
        drop(store.read_soon::<u32>(&job.name));
        let writing = std::thread::spawn({
            let job = job.clone();
            move || job.keep()
        });
        while job.writing.try_lock().is_ok() {
            std::thread::yield_now();
        }
        job.forget();
        assert_eq!(job.stage(), Stage::Over);
        release.send(()).unwrap();
        assert!(!writing.join().unwrap());
        assert!(store.load::<serde_json::Value>(&job.name).is_none());
        assert!(job.send().is_none(), "taken back: never sent");
    }

    #[test]
    fn a_kept_message_is_written_compactly_and_reads_back() {
        let store = Arc::new(Store::temp());
        let bytes: Vec<u8> = (0..=255).cycle().take(30_000).collect();
        let job = Job::new(
            String::new(),
            1,
            client(),
            Some(store.clone()),
            with_file(bytes.clone()),
        )
        .unwrap();
        assert!(job.keep() && job.kept());
        let raw: serde_json::Value = store.load(&job.name).unwrap();
        let written = raw["mail"]["outgoing"]["files"][0]["bytes"]
            .as_str()
            .unwrap();
        assert!(
            written.len() < bytes.len() * 3 / 2,
            "base64, not a list of numbers"
        );
        drop(job.state().claim.take());
        let found = Job::left_behind("", &client(), &store);
        assert_eq!(found[0].mail().1.files[0].bytes, bytes);
        assert_eq!(found[0].stage(), Stage::Held);
    }

    #[test]
    fn a_message_kept_by_an_earlier_version_still_reads_back() {
        let store = Arc::new(Store::temp());
        // As written before files were base64: each byte a number.
        let old = serde_json::json!({
            "stage": "Held",
            "mail": {
                "draft_id": "r123",
                "outgoing": {
                    "to": "ana@example.com", "cc": "", "bcc": "", "subject": "Old",
                    "body": "Hi", "html": null, "kept": [], "reply": null,
                    "files": [{"name": "a.txt", "mime": "text/plain", "bytes": [104, 105, 0, 255]}]
                }
            }
        });
        store.save("sending-0123456789abcdef", &old).unwrap();
        let found = Job::left_behind("", &client(), &store);
        let (draft, outgoing) = found[0].mail();
        assert_eq!(draft.as_deref(), Some("r123"));
        assert_eq!(outgoing.files[0].bytes, [104, 105, 0, 255]);
        assert_eq!(found[0].subject(), "Old");
    }
}
