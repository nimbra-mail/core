//! What is still on its way to the server, and what quitting does about it: wait a while,
//! and have on disk whatever might not make it. Changes to one thread go in order (`Steps`).

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::Instant;

use crate::mail;
use crate::scheduled::{self, Scheduled};
use crate::sending::{self, Job};
use crate::store::Store;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Counts work that quitting waits for.
#[derive(Clone, Default)]
pub struct Underway(Arc<(Mutex<usize>, Condvar)>);

/// One piece of that work, until dropped.
pub struct Working(Underway);

impl Underway {
    /// Called before the work is handed to another thread, and moved into it.
    pub fn begin(&self) -> Working {
        *locked(&self.0.0) += 1;
        Working(self.clone())
    }

    pub fn any(&self) -> bool {
        *locked(&self.0.0) > 0
    }

    fn wait(&self, deadline: Instant) {
        let left = deadline.saturating_duration_since(Instant::now());
        let count = locked(&self.0.0);
        drop(self.0.1.wait_timeout_while(count, left, |count| *count > 0));
    }
}

impl Drop for Working {
    fn drop(&mut self) {
        let underway = &*self.0.0;
        *locked(&underway.0) -= 1;
        underway.1.notify_all();
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum End {
    Through,
    /// Gmail was not reached.
    Offline,
    /// Gmail failed or said no.
    Failed,
}

/// One change to a thread (Done, Trash, a star), from the action until it is settled.
/// Those of one thread go in order, or Done followed at once by Undo could land reversed.
pub struct Step {
    pub account: String,
    pub id: String,
    pub change: mail::Change,
    before: Mutex<Option<Arc<Step>>>,
    end: Mutex<Option<End>>,
    ended: Condvar,
}

impl Step {
    /// Waits for the thread's change before it, then makes this one. Blocking.
    pub fn run(&self, client: &mail::Client) -> anyhow::Result<()> {
        self.run_with(|| client.change(&self.id, self.change))
    }

    fn run_with(&self, make: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<()> {
        let before = locked(&self.before).take();
        // That one will be made again later, and this one has to follow it.
        let result = match before.map(|step| step.wait()) {
            Some(End::Offline) => Err(mail::Offline.into()),
            _ => make(),
        };
        *locked(&self.end) = Some(match &result {
            Ok(()) => End::Through,
            Err(error) if error.is::<mail::Offline>() => End::Offline,
            Err(_) => End::Failed,
        });
        self.ended.notify_all();
        result
    }

    fn wait(&self) -> End {
        let end = self
            .ended
            .wait_while(locked(&self.end), |end| end.is_none());
        end.unwrap_or_else(PoisonError::into_inner)
            .unwrap_or(End::Failed)
    }

    fn end(&self) -> Option<End> {
        *locked(&self.end)
    }
}

/// The changes that are not settled, in the order they were made.
#[derive(Default)]
pub struct Steps(Vec<Arc<Step>>);

impl Steps {
    pub fn start(&mut self, account: String, id: String, change: mail::Change) -> Arc<Step> {
        let before = self
            .0
            .iter()
            .rev()
            .find(|step| step.account == account && step.id == id)
            .cloned();
        let step = Arc::new(Step {
            account,
            id,
            change,
            before: Mutex::new(before),
            end: Mutex::new(None),
            ended: Condvar::new(),
        });
        self.0.push(step.clone());
        step
    }

    /// Takes out a thread's changes that have ended, up to the first that has not. Their
    /// answers can arrive out of order, and what goes into the offline queue must not.
    pub fn settle(&mut self, account: &str, id: &str) -> Vec<(Arc<Step>, End)> {
        let mut settled = Vec::new();
        let mut waiting = false;
        self.0.retain(|step| {
            if waiting || step.account != account || step.id != id {
                return true;
            }
            let Some(end) = step.end() else {
                waiting = true;
                return true;
            };
            settled.push((step.clone(), end));
            false
        });
        settled
    }

    pub fn forget(&mut self, account: &str) {
        self.0.retain(|step| step.account != account);
    }

    pub fn all(&self) -> Vec<Arc<Step>> {
        self.0.clone()
    }
}

/// What a draft save left in Gmail: the draft's id and the edit count it has.
pub type SavedAs = Arc<Mutex<Option<(String, u64)>>>;

/// Something still being written, being scheduled, or just discarded.
pub struct Unfinished {
    pub job: Arc<Job>,
    pub edits: u64,
    pub saved: SavedAs,
    /// When to send it, and whose list that goes in.
    pub later: Option<(String, Option<Arc<Store>>, Scheduled)>,
}

/// An account's changes that may not make it, with those that waited already.
pub struct Changes {
    pub account: String,
    pub store: Option<Arc<Store>>,
    /// Made offline before the store was open, so not on disk yet.
    pub unsaved: Vec<(String, mail::Change)>,
    pub steps: Vec<Arc<Step>>,
}

pub struct Leaving {
    pub sends: Vec<(Arc<Job>, SavedAs)>,
    pub unfinished: Vec<Unfinished>,
    pub changes: Vec<Changes>,
    pub saves: Underway,
    pub writes: Underway,
}

impl Leaving {
    pub fn is_empty(&self) -> bool {
        self.sends.is_empty()
            && self.unfinished.is_empty()
            && self.changes.is_empty()
            && !self.saves.any()
            && !self.writes.any()
    }

    /// Returns at the deadline at the latest, even if the keychain never answers.
    pub fn finish(self, deadline: Instant) {
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            self.work(deadline);
            done.send(()).ok();
        });
        // A moment more, for writing down what the deadline cut off.
        let left = deadline.saturating_duration_since(Instant::now());
        let _ = finished.recv_timeout(left + std::time::Duration::from_secs(1));
    }

    fn work(self, deadline: Instant) {
        let Leaving {
            sends,
            unfinished,
            changes,
            saves,
            writes,
        } = self;
        // On disk before anything is waited for: being killed while waiting loses nothing.
        for item in &unfinished {
            item.job.keep();
        }
        let queues: Vec<_> = changes.into_iter().filter_map(Queue::keep).collect();

        // A save that is out tells which draft to send, or to write over.
        saves.wait(deadline);
        let mut jobs = Vec::new();
        for (job, saved) in sends {
            job.set_draft(locked(&saved).clone().map(|(id, _)| id));
            jobs.push(job);
        }
        let (done, finished) = mpsc::channel();
        let count = unfinished.len();
        for item in unfinished {
            let done = done.clone();
            std::thread::spawn(move || {
                item.finish();
                done.send(()).ok();
            });
        }
        sending::finish(&jobs, deadline);
        for _ in 0..count {
            let left = deadline.saturating_duration_since(Instant::now());
            if finished.recv_timeout(left).is_err() {
                break;
            }
        }
        writes.wait(deadline);
        for queue in &queues {
            queue.save();
        }
    }
}

impl Unfinished {
    fn finish(self) {
        let saved = locked(&self.saved).clone();
        if self.job.stage() == sending::Stage::Discarded {
            self.job.set_draft(saved.map(|(id, _)| id));
            self.job.discard();
            return;
        }
        let id = match saved {
            Some((id, edits)) if edits == self.edits => {
                self.job.forget();
                Some(id)
            }
            saved => {
                self.job.set_draft(saved.map(|(id, _)| id));
                self.job.saved_as_draft()
            }
        };
        let (Some(draft_id), Some((account, store, item))) = (id, self.later) else {
            return;
        };
        let store = store.or_else(|| Store::open_quietly(&account).ok().map(Arc::new));
        let kept = store
            .is_some_and(|store| scheduled::add(&store, Scheduled { draft_id, ..item }).is_ok());
        if !kept {
            eprintln!("nimbra: could not save the send-later list");
        }
    }
}

/// An account's offline queue as quitting leaves it.
struct Queue {
    store: Arc<Store>,
    before: Vec<(String, mail::Change)>,
    steps: Vec<Arc<Step>>,
}

impl Queue {
    fn keep(changes: Changes) -> Option<Self> {
        let store = match changes.store {
            Some(store) => store,
            None => Arc::new(Store::open_quietly(&changes.account).ok()?),
        };
        let mut before = store
            .load::<crate::outbox::Outbox>("outbox")
            .unwrap_or_default()
            .changes;
        before.extend(changes.unsaved);
        let queue = Self {
            store,
            before,
            steps: changes.steps,
        };
        queue.save();
        Some(queue)
    }

    /// Everything that has not got through by now. Making a change twice does no harm.
    fn save(&self) {
        let mut all = self.before.clone();
        all.extend(
            self.steps
                .iter()
                .filter(|step| step.end() != Some(End::Through))
                .map(|step| (step.id.clone(), step.change)),
        );
        let saved = self
            .store
            .update("outbox", |outbox: &mut crate::outbox::Outbox| {
                outbox.changes = all
            });
        if saved.is_err() {
            eprintln!("nimbra: could not save the offline queue");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_follows_the_one_before_it_into_the_offline_queue_in_order() {
        let mut steps = Steps::default();
        let new = |steps: &mut Steps, change| steps.start(String::new(), "t".into(), change);
        let done = new(&mut steps, mail::Change::Archive);
        let undo = new(&mut steps, mail::Change::Unarchive);
        let after = std::thread::spawn({
            let undo = undo.clone();
            move || undo.run_with(|| panic!("must not be sent before the one it follows"))
        });
        assert!(steps.settle("", "t").is_empty());
        assert!(done.run_with(|| Err(mail::Offline.into())).is_err());
        assert!(after.join().unwrap().is_err());
        let settled = steps.settle("", "t");
        assert!(Arc::ptr_eq(&settled[0].0, &done) && Arc::ptr_eq(&settled[1].0, &undo));
        assert!(settled.iter().all(|(_, end)| *end == End::Offline));
    }

    #[test]
    fn a_refused_change_does_not_hold_up_the_next() {
        let mut steps = Steps::default();
        let first = steps.start(String::new(), "t".into(), mail::Change::Star);
        let next = steps.start(String::new(), "t".into(), mail::Change::Unstar);
        let other = steps.start(String::new(), "u".into(), mail::Change::Star);
        assert!(first.run_with(|| Err(anyhow::anyhow!("no"))).is_err());
        assert!(next.run_with(|| Ok(())).is_ok());
        assert_eq!(steps.settle("", "t").len(), 2);
        assert!(Arc::ptr_eq(&steps.all()[0], &other));
    }

    #[test]
    fn quitting_keeps_what_was_queued_while_the_stored_queue_was_read_after_it() {
        let (store, release) = Store::temp_held();
        let mut stored = crate::outbox::Outbox::default();
        stored.changes.push(("a".into(), mail::Change::Archive));
        store.save_soon("outbox", stored);
        let quitting = std::thread::spawn({
            let store = store.clone();
            move || {
                Queue::keep(Changes {
                    account: String::new(),
                    store: Some(store),
                    unsaved: vec![("b".into(), mail::Change::MarkRead)],
                    steps: Vec::new(),
                })
                .is_some()
            }
        });
        release.send(()).unwrap();
        assert!(quitting.join().unwrap());
        let kept: crate::outbox::Outbox = Store::temp_like(&store).load("outbox").unwrap();
        let ids: Vec<&str> = kept.changes.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
    }

    #[test]
    fn waiting_ends_with_the_work_or_at_the_deadline() {
        let underway = Underway::default();
        let working = underway.begin();
        underway.wait(Instant::now() + std::time::Duration::from_millis(20));
        assert!(underway.any());
        std::thread::spawn(move || drop(working));
        underway.wait(Instant::now() + std::time::Duration::from_secs(5));
        assert!(!underway.any());
    }
}
