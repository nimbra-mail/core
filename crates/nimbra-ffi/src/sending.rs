//! `Engine`: sending, as the macOS app sends (`nimbra_core::sending`, `outbox`,
//! `scheduled`): a message is kept on the device from Send until the server has it, can be
//! taken back during its undo time, waits for the connection when offline, and is never
//! sent twice by itself. The app owns the timers: `pending_work` says when to look again.

use std::sync::Arc;

use nimbra_core::outbox::{self, Failed, NotReady, PickUp};
use nimbra_core::sending::{self, Job, Stage};
use nimbra_core::{mail, scheduled, snooze};

use crate::engine::{Engine, locked, now_ms};
use crate::error::{NimbraError, Result};
use crate::types::*;

/// A message on its way: kept on the device from `queue_send` until the server has it.
#[derive(uniffi::Object)]
pub struct OutgoingSend {
    pub(crate) job: Arc<Job>,
    /// When its undo time is over (ms since 1970): hand it over then (`deliver`).
    deliver_at_ms: i64,
}

impl OutgoingSend {
    fn new(job: Arc<Job>, deliver_at_ms: i64) -> Arc<Self> {
        Arc::new(OutgoingSend { job, deliver_at_ms })
    }
}

#[uniffi::export]
impl OutgoingSend {
    /// The account it is sent from. Memory only.
    pub fn account_id(&self) -> String {
        self.job.account.clone()
    }

    /// Its subject, for a notice. Memory only.
    pub fn subject(&self) -> String {
        self.job.subject()
    }

    /// Where it is on its way. Memory only.
    pub fn stage(&self) -> SendStage {
        self.job.stage().into()
    }

    /// When the undo time is over and it is to be handed over (`deliver`). Memory only.
    pub fn deliver_at_ms(&self) -> i64 {
        self.deliver_at_ms
    }

    /// The message as it is now, to show again after Undo. Memory only.
    pub fn message(&self) -> OutgoingMessage {
        let (_, outgoing) = self.job.mail();
        OutgoingMessage::from(outgoing.as_ref())
    }

    /// Whether it is kept on the device (so quitting cannot lose it). Memory only.
    pub fn is_kept(&self) -> bool {
        self.job.kept()
    }

    /// Hands it to the server, once however often this is called, and says what became of
    /// it, as the Mac decides: sent; waiting for the connection (it is sent by `catch_up`);
    /// it may have gone (saved to Drafts, never sent again by itself); or refused (show the
    /// message again, or `save_to_drafts`). Network.
    pub fn deliver(&self) -> SendOutcome {
        let Some(result) = self.job.send() else {
            return SendOutcome::NotWaiting;
        };
        let error = match result {
            Ok(()) => return SendOutcome::Sent,
            Err(error) => error,
        };
        if error.is::<mail::SignedOut>() {
            return SendOutcome::SignedOut;
        }
        match outbox::failed(&error) {
            Failed::Offline => SendOutcome::WaitingForConnection,
            Failed::Unsure => SendOutcome::MaybeSent {
                in_drafts: self.job.to_drafts(),
            },
            Failed::Refused => SendOutcome::Refused {
                message: format!("{error:#}"),
            },
        }
    }

    /// Undo send, or taking a refused message back to edit: nothing is left of it on the
    /// device. Whether it was taken back (not once it has left). Disk.
    pub fn undo(&self) -> bool {
        if !matches!(self.job.stage(), Stage::Held | Stage::Refused) {
            return false;
        }
        self.job.forget();
        true
    }

    /// Puts it in Drafts instead. Its draft id, or `None` while that has not worked yet (it
    /// stays kept). Network.
    pub fn save_to_drafts(&self) -> Option<String> {
        self.job.saved_as_draft()
    }

    /// Deletes it and whatever draft was saved of it. Whether that worked. Network.
    pub fn discard(&self) -> bool {
        self.job.discard()
    }
}

fn not_ready(why: NotReady) -> NimbraError {
    NimbraError::invalid(match why {
        NotReady::Recipients(error) => error,
        NotReady::Empty => "Write a subject or a message first.".into(),
        NotReady::TooLarge => "Attachments can be 25 MB in total.".into(),
    })
}

fn moved(job: &Job, why: LeftBehind) -> MovedToDrafts {
    MovedToDrafts {
        subject: job.subject(),
        why,
        in_drafts: job.to_drafts(),
    }
}

#[uniffi::export]
impl Engine {
    /// Send: checks the message as the Mac does, keeps it on the device and hands it back,
    /// held. `deliver` it at `deliver_at_ms` (now plus the undo time in Preferences), or
    /// `undo` it before. `draft_id` is its saved draft, which sending uses up. Disk and
    /// Keychain.
    pub fn queue_send(
        &self,
        account_id: String,
        message: OutgoingMessage,
        draft_id: Option<String>,
    ) -> Result<Arc<OutgoingSend>> {
        let outgoing = mail::Outgoing::from(&message);
        outbox::ready(&outgoing).map_err(not_ready)?;
        let open = self.connect(&account_id)?;
        let serial = {
            let mut sends = locked(&self.sends);
            *sends += 1;
            *sends
        };
        let job = Job::new(
            account_id,
            serial,
            open.client.clone(),
            Some(open.store.clone()),
            sending::QueuedMail { draft_id, outgoing },
        )?;
        // Not kept: it can still be sent, but quitting before then loses it (`is_kept`).
        job.keep_asking();
        let undo = outbox::undo_delay(self.preferences().undo_send_seconds);
        Ok(OutgoingSend::new(
            job,
            now_ms() + i64::try_from(undo.as_millis()).unwrap_or(0),
        ))
    }

    /// What an earlier run left unsent for this account, as the Mac picks it up: what never
    /// left comes back to be sent (`deliver`); what may have gone, was refused, was still
    /// being written or was not scheduled goes to Drafts (listed, to say so); what was
    /// discarded is deleted. Network.
    pub fn unsent(&self, account_id: String) -> Result<UnsentReport> {
        let open = self.connect(&account_id)?;
        let mut report = UnsentReport {
            to_send: Vec::new(),
            moved_to_drafts: Vec::new(),
        };
        for job in Job::left_behind(&account_id, &open.client, &open.store) {
            match outbox::pick_up(job.stage()) {
                PickUp::Send => report.to_send.push(OutgoingSend::new(job, now_ms())),
                PickUp::MaybeSent => report
                    .moved_to_drafts
                    .push(moved(&job, LeftBehind::MaybeSent)),
                PickUp::Refused => report
                    .moved_to_drafts
                    .push(moved(&job, LeftBehind::Refused)),
                PickUp::Writing => report
                    .moved_to_drafts
                    .push(moved(&job, LeftBehind::Writing)),
                PickUp::Unscheduled => report
                    .moved_to_drafts
                    .push(moved(&job, LeftBehind::Unscheduled)),
                PickUp::Discard => {
                    job.discard();
                }
                PickUp::Forget => job.forget(),
            }
        }
        Ok(report)
    }

    /// A message `deliver` left waiting for the connection: `catch_up` sends it.
    /// Memory only.
    pub fn wait_for_connection(&self, send: Arc<OutgoingSend>) {
        let mut waiting = locked(&self.waiting);
        let queue = waiting.entry(send.job.account.clone()).or_default();
        if !queue.iter().any(|job| Arc::ptr_eq(job, &send.job)) {
            queue.push(send.job.clone());
        }
    }

    /// Back online (or `pending_work` said so): makes the changes that waited, in order,
    /// then sends the messages that waited. Fails as offline while the server cannot be
    /// reached. Network.
    pub fn catch_up(&self, account_id: String) -> Result<CatchUpResult> {
        let open = self.connect(&account_id)?;
        let changes = outbox::load(&open.store).changes;
        let queue: Vec<Arc<Job>> = locked(&self.waiting)
            .get(&account_id)
            .cloned()
            .unwrap_or_default();
        let done = outbox::catch_up(&*open.client, &changes, &queue)?;
        let left = outbox::drop_caught_up(&open.store, done.changes)?;
        let mut waiting = locked(&self.waiting);
        if let Some(queue) = waiting.get_mut(&account_id) {
            queue.retain(|job| matches!(job.stage(), Stage::Held | Stage::Out));
        }
        let still_waiting = waiting
            .get(&account_id)
            .is_some_and(|queue| !queue.is_empty());
        Ok(CatchUpResult {
            changes: done.changes as u32,
            sent: done.sent as u32,
            moved_to_drafts: done
                .kept
                .into_iter()
                .map(|(subject, unsure, in_drafts)| MovedToDrafts {
                    subject,
                    why: if unsure {
                        LeftBehind::MaybeSent
                    } else {
                        LeftBehind::Refused
                    },
                    in_drafts,
                })
                .collect(),
            done: !left && !still_waiting,
        })
    }

    /// What waits for this account, and when to look again: the soonest snooze or send
    /// later, or the next retry while something waits for the connection. Schedule a timer
    /// or a background task for `next_deadline_ms`, then call `wake_due`, `send_due` and
    /// `catch_up`. Disk.
    pub fn pending_work(&self, account_id: String) -> Result<PendingWork> {
        let open = self.connect(&account_id)?;
        let queued_changes = outbox::load(&open.store).changes.len() as u32;
        let waiting_messages = locked(&self.waiting)
            .get(&account_id)
            .map_or(0, |queue| queue.len()) as u32;
        let retry = (queued_changes > 0 || waiting_messages > 0)
            .then(|| now_ms() + i64::try_from(outbox::RETRY_EVERY.as_millis()).unwrap_or(15_000));
        let next = [
            snooze::next_due(&snooze::list(&open.store)),
            scheduled::next_due(&open.store),
            retry,
        ]
        .into_iter()
        .flatten()
        .min();
        Ok(PendingWork {
            queued_changes,
            waiting_messages,
            next_deadline_ms: next,
        })
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
        outbox::ready(&outgoing).map_err(not_ready)?;
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

    /// Sends the send-later messages kept with this account that are due, each from its
    /// draft's own account. The drafts sent (or found gone). Network.
    pub fn send_due(&self, account_id: String) -> Result<Vec<String>> {
        let open = self.connect(&account_id)?;
        let now = now_ms();
        let mut sent = Vec::new();
        for item in scheduled::list(&open.store) {
            if item.at_ms > now {
                continue;
            }
            let owner = item.account.clone().unwrap_or_else(|| account_id.clone());
            let Ok(theirs) = self.connect(&owner) else {
                continue; // not connected: later
            };
            if scheduled::send(&open.store, &*theirs.client, &item.draft_id).is_some() {
                sent.push(item.draft_id);
            }
        }
        Ok(sent)
    }
}

/// The times Send later offers from now. Memory only.
#[uniffi::export]
pub fn send_later_times() -> Vec<SendLaterTime> {
    use nimbra_core::scheduled::Later;
    scheduled::later_times(chrono::Local::now())
        .into_iter()
        .map(|(kind, when)| SendLaterTime {
            kind: match kind {
                Later::InAnHour => SendLaterKind::InAnHour,
                Later::ThisEvening => SendLaterKind::ThisEvening,
                Later::TomorrowMorning => SendLaterKind::TomorrowMorning,
                Later::MondayMorning => SendLaterKind::MondayMorning,
            },
            at_ms: when.timestamp_millis(),
        })
        .collect()
}
