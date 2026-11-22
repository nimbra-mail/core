//! A message from Send until Gmail has it. It is kept in its account's store meanwhile, so
//! that quitting or switching accounts cannot lose it, and one that may already have gone
//! out is never sent again by itself. What was being written at quit is kept the same way,
//! for Drafts only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::gmail;
use crate::store::Store;

const RECORD: &str = "sending-";

#[derive(Clone, Serialize, Deserialize)]
pub struct QueuedMail {
    pub draft_id: Option<String>,
    pub outgoing: gmail::Outgoing,
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

struct State {
    record: Record,
    store: Option<Arc<Store>>,
    /// Held for as long as this copy of Nimbra looks after the message, so that another
    /// does not send it as left behind. The system lets go of it however the app ends.
    claim: Option<std::fs::File>,
}

pub struct Job {
    pub account: String,
    /// The composer it came from; none for one found at launch.
    pub composer: Option<u64>,
    client: Arc<gmail::Client>,
    name: String,
    /// It is on disk. Outside the lock, which a write holds while the keychain is asked.
    kept: AtomicBool,
    state: Mutex<State>,
    changed: Condvar,
}

impl Job {
    /// `store` is the account's when that is open; otherwise `keep` opens it.
    pub fn new(
        account: String,
        composer: u64,
        client: Arc<gmail::Client>,
        store: Option<Arc<Store>>,
        mail: QueuedMail,
    ) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            account,
            composer: Some(composer),
            client,
            name: format!("{RECORD}{}", gmail::random_hex(8)?),
            kept: AtomicBool::new(false),
            state: Mutex::new(State {
                record: Record {
                    stage: Stage::Held,
                    mail,
                },
                store,
                claim: None,
            }),
            changed: Condvar::new(),
        }))
    }

    /// One that was still open at quit: `stage` is `Writing`, `Unscheduled` or `Discarded`.
    pub fn unfinished(
        account: String,
        composer: u64,
        client: Arc<gmail::Client>,
        store: Option<Arc<Store>>,
        mail: QueuedMail,
        stage: Stage,
    ) -> anyhow::Result<Arc<Self>> {
        let job = Job::new(account, composer, client, store, mail)?;
        job.state.lock().unwrap().record.stage = stage;
        Ok(job)
    }

    /// One from the offline queue of earlier versions.
    pub fn queued(
        account: &str,
        client: &Arc<gmail::Client>,
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
        client: &Arc<gmail::Client>,
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
            found.push(Arc::new(Self {
                account: account.to_string(),
                composer: None,
                client: client.clone(),
                name,
                kept: AtomicBool::new(true),
                state: Mutex::new(State {
                    record,
                    store: Some(store.clone()),
                    claim: Some(claim),
                }),
                changed: Condvar::new(),
            }));
        }
        found
    }

    pub fn stage(&self) -> Stage {
        self.state.lock().unwrap().record.stage
    }

    pub fn subject(&self) -> String {
        self.state
            .lock()
            .unwrap()
            .record
            .mail
            .outgoing
            .subject
            .clone()
    }

    fn mail(&self) -> QueuedMail {
        self.state.lock().unwrap().record.mail.clone()
    }

    /// Writes it down; whether that worked. Blocking.
    pub fn keep(&self) -> bool {
        self.write(&mut self.state.lock().unwrap())
    }

    /// The same on Send, which is worth asking the keychain again for. Blocking.
    pub fn keep_asking(&self) -> bool {
        if Store::unreadable(&self.account)
            && let Ok(store) = Store::open(&self.account)
        {
            // Not under the lock while asking: the main thread takes that too.
            self.state
                .lock()
                .unwrap()
                .store
                .get_or_insert(Arc::new(store));
        }
        self.keep()
    }

    /// Whether it is on disk.
    pub fn kept(&self) -> bool {
        self.kept.load(Ordering::Relaxed)
    }

    fn write(&self, state: &mut State) -> bool {
        if state.record.stage == Stage::Over {
            return false;
        }
        if state.store.is_none() {
            state.store = Store::open_quietly(&self.account).ok().map(Arc::new);
        }
        let Some(store) = state.store.clone() else {
            return false;
        };
        if state.claim.is_none() {
            state.claim = store.claim(&self.name);
        }
        let saved = store.save(&self.name, &state.record).is_ok();
        self.kept.store(saved, Ordering::Relaxed);
        if !saved {
            eprintln!("nimbra: could not save the message being sent");
        }
        saved
    }

    /// Taken back or handed on: nothing is left of it on disk. This does not wait for a
    /// background thread, as quitting straight after Undo must not send it.
    pub fn forget(&self) {
        let mut state = self.state.lock().unwrap();
        state.record.stage = Stage::Over;
        if let Some(store) = &state.store {
            store.remove(&self.name);
        }
        self.changed.notify_all();
    }

    /// The draft saved since Send, which sending then uses up.
    pub fn set_draft(&self, draft_id: Option<String>) {
        if draft_id.is_some() {
            self.state.lock().unwrap().record.mail.draft_id = draft_id;
        }
    }

    /// Sends it, once however often it is called: `None` if it was not waiting. Blocking.
    pub fn send(&self) -> Option<anyhow::Result<()>> {
        let mail = {
            let mut state = self.state.lock().unwrap();
            if state.record.stage != Stage::Held {
                return None;
            }
            state.record.stage = Stage::Out;
            self.write(&mut state);
            state.record.mail.clone()
        };
        let result = match &mail.draft_id {
            Some(id) => self.client.send_draft(id, &mail.outgoing),
            None => self.client.send_message(&mail.outgoing),
        };
        let mut state = self.state.lock().unwrap();
        if state.record.stage == Stage::Out {
            state.record.stage = match &result {
                Ok(()) => Stage::Over,
                Err(error) if error.is::<gmail::MayHaveArrived>() => Stage::Unsure,
                Err(error) if error.is::<gmail::Offline>() => Stage::Held,
                Err(_) => Stage::Refused,
            };
            if state.record.stage == Stage::Over {
                if let Some(store) = &state.store {
                    store.remove(&self.name);
                }
            } else {
                self.write(&mut state);
            }
        }
        self.changed.notify_all();
        Some(result)
    }

    /// Puts it in Gmail's Drafts. Until that works it stays on disk. Blocking.
    pub fn to_drafts(&self) -> bool {
        self.saved_as_draft().is_some()
    }

    /// The same, for who needs the draft's id.
    pub fn saved_as_draft(&self) -> Option<String> {
        let mail = self.mail();
        let id = self
            .client
            .keep_as_draft(mail.draft_id.as_deref(), &mail.outgoing)
            .ok()?;
        self.forget();
        Some(id)
    }

    /// Deletes what was saved of a discarded message. Until that works it stays on disk.
    /// Blocking.
    pub fn discard(&self) -> bool {
        let deleted = match self.mail().draft_id {
            None => true,
            Some(id) => match self.client.delete_draft(&id) {
                Ok(()) => true,
                Err(error) => gmail::is_gone(&error),
            },
        };
        if deleted {
            self.forget();
        }
        deleted
    }

    fn wait(&self) {
        let state = self.state.lock().unwrap();
        drop(
            self.changed
                .wait_while(state, |state| state.record.stage == Stage::Out)
                .unwrap(),
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
