//! The people the user writes with, for address suggestions in the composer's To, Cc and
//! Bcc. Each account's connection learns them from the mail that passes through it (list
//! rows, threads opened, messages sent: see [`Learning`]) and, once, from the headers of its
//! newest sent and received mail ([`Contacts::scan_step`]). Kept in the account's
//! encrypted store on this Mac, and asked of nobody else.
//!
//! Learning is idempotent: a person keeps the times of the messages they were seen in, not
//! a count, so the same list row listed again changes nothing (and saves nothing).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::mail::{
    self, Change, Changes, Client, Draft, Label, Message, Met, Outgoing, Person, Photo, Provider,
    Summary, View,
};
use crate::store::Store;

/// The store record.
const KEY: &str = "contacts";
/// The most people kept for an account: the lowest scored go first.
const MOST_PEOPLE: usize = 3000;
/// The times kept of each kind (sent to, seen with), newest first.
const TIMES_KEPT: usize = 8;
/// How many of the newest sent and received messages the first look reads.
const SENT_MOST: usize = 2000;
const RECEIVED_MOST: usize = 1000;
/// The wait between two pages of the first look. A Gmail page is about 500 units, so this
/// keeps it near 2,000 of the 6,000 a minute Gmail allows each user.
pub const SCAN_PAUSE: Duration = Duration::from_secs(15);
/// The most suggestions shown.
pub const SHOWN: usize = 5;
/// A name longer than this is not one (it is kept cut).
const NAME_MOST: usize = 120;

const DAY_MS: f64 = 86_400_000.0;

/// Everything kept of one account.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Book {
    /// By lowercase address.
    people: HashMap<String, Known>,
    #[serde(default)]
    sent_scan: Scan,
    #[serde(default)]
    received_scan: Scan,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Known {
    name: String,
    /// When the user wrote to them (milliseconds since the epoch), newest first.
    #[serde(default)]
    sent: Vec<i64>,
    /// When they were in mail the user got.
    #[serde(default)]
    seen: Vec<i64>,
}

/// How far the first look through one mailbox has got.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Scan {
    next: Option<String>,
    taken: usize,
    done: bool,
}

#[derive(Clone, Copy)]
enum Kind {
    Sent,
    Seen,
}

impl Known {
    /// Notes a message at `at`; says whether anything changed.
    fn note(&mut self, name: &str, kind: Kind, at: i64) -> bool {
        let newest = self.sent.first().max(self.seen.first()).copied();
        let times = match kind {
            Kind::Sent => &mut self.sent,
            Kind::Seen => &mut self.seen,
        };
        let mut changed = false;
        if !times.contains(&at) {
            let place = times.partition_point(|t| *t > at);
            if place < TIMES_KEPT {
                times.insert(place, at);
                times.truncate(TIMES_KEPT);
                changed = true;
            }
        }
        // The newest name a person goes by wins; an empty one never replaces one.
        if !name.is_empty()
            && self.name != name
            && newest.is_none_or(|n| at >= n || self.name.is_empty())
        {
            self.name = name.to_string();
            changed = true;
        }
        changed
    }

    /// Higher for people written to, and for recent mail.
    fn score(&self, now: i64) -> f64 {
        let weight = |at: &i64| 1.0 / (1.0 + ((now - at).max(0) as f64 / DAY_MS) / 60.0);
        4.0 * self.sent.iter().map(weight).sum::<f64>() + self.seen.iter().map(weight).sum::<f64>()
    }

    fn merge(&mut self, other: &Known) {
        for at in &other.sent {
            self.note("", Kind::Sent, *at);
        }
        for at in &other.seen {
            self.note("", Kind::Seen, *at);
        }
        if self.name.is_empty() {
            self.name = other.name.clone();
        }
    }
}

impl Book {
    /// Takes in one message; says whether anything changed.
    fn learn(&mut self, met: &Met, me: &[String]) -> bool {
        let mine = |address: &str| me.iter().any(|m| m.eq_ignore_ascii_case(address.trim()));
        let sent = met.sent || mine(&met.from.address);
        let mut changed = false;
        let others = met.to.iter().chain(&met.cc);
        if sent {
            for person in others {
                changed |= self.note(person, Kind::Sent, met.timestamp_ms, &mine);
            }
        } else {
            for person in std::iter::once(&met.from).chain(others) {
                // Mail from machines is never suggested unless the user writes to it.
                if !automated(&person.address) {
                    changed |= self.note(person, Kind::Seen, met.timestamp_ms, &mine);
                }
            }
        }
        changed
    }

    fn note(&mut self, person: &Person, kind: Kind, at: i64, mine: &impl Fn(&str) -> bool) -> bool {
        let address = person.address.trim().to_lowercase();
        if !mail::is_address(&address) || mine(&address) {
            return false;
        }
        let name = clean_name(&person.name, &address);
        self.people
            .entry(address)
            .or_default()
            .note(&name, kind, at)
    }

    /// Keeps the book to its size: the people least likely to be wanted go.
    fn prune(&mut self, now: i64) {
        if self.people.len() <= MOST_PEOPLE {
            return;
        }
        let mut scored: Vec<(f64, String)> = self
            .people
            .iter()
            .map(|(address, known)| (known.score(now), address.clone()))
            .collect();
        scored.sort_by(|a, b| b.0.total_cmp(&a.0));
        for (_, address) in scored.into_iter().skip(MOST_PEOPLE) {
            self.people.remove(&address);
        }
    }

    fn merge(&mut self, other: &Book) {
        for (address, known) in &other.people {
            self.people.entry(address.clone()).or_default().merge(known);
        }
    }
}

/// A name fit to show: one line, not the address again, not too long.
fn clean_name(name: &str, address: &str) -> String {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if name.eq_ignore_ascii_case(address) {
        return String::new();
    }
    name.chars().take(NAME_MOST).collect()
}

/// An address that sends mail nobody answers: no-reply, bounces, notifications.
pub fn automated(address: &str) -> bool {
    let local = address
        .split('@')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .replace(['-', '_', '.'], "");
    [
        "noreply",
        "donotreply",
        "mailerdaemon",
        "postmaster",
        "bounce",
        "notification",
        "notify",
        "unsubscribe",
        "newsletter",
    ]
    .iter()
    .any(|word| local.contains(word))
}

/// Whether what is being typed (`token`, lowercase) starts the person's address, a word of
/// The people whose name, address or domain starts with `token`, best first, across
/// accounts: what each account's `Contacts` learnt (`books`, by account id; the account the
/// message is written `from` counts double), and the people of the mail on screen (`seen`,
/// a little). Never the user's own addresses (`mine`, lowercase), nor anyone already in
/// the field (`present`, lowercase). At most `SHOWN`.
pub fn rank<'a>(
    token: &str,
    from: &str,
    books: impl IntoIterator<Item = (&'a str, &'a Contacts)>,
    seen: impl IntoIterator<Item = &'a Person>,
    mine: &[String],
    present: &[String],
) -> Vec<Person> {
    let mut found: HashMap<String, (Person, f64)> = HashMap::new();
    let mut add = |person: Person, score: f64| {
        let key = person.address.to_lowercase();
        if key.is_empty() || mine.contains(&key) || present.contains(&key) {
            return;
        }
        let entry = found.entry(key).or_insert_with(|| (person.clone(), 0.0));
        entry.1 += score;
        if entry.0.name.is_empty() && !person.name.is_empty() {
            entry.0.name = person.name;
        }
    };
    for (account, book) in books {
        let weight = if account == from { 2.0 } else { 1.0 };
        for (person, score) in book.suggest(token) {
            add(person, score * weight);
        }
    }
    for person in seen {
        if matches(person, token) && !automated(&person.address) {
            add(person.clone(), 0.25);
        }
    }
    let mut found: Vec<(Person, f64)> = found.into_values().collect();
    found.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| a.0.address.cmp(&b.0.address))
    });
    found.into_iter().take(SHOWN).map(|(p, _)| p).collect()
}

/// their name, or the address's domain.
pub fn matches(person: &Person, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let address = person.address.to_lowercase();
    let name = person.name.to_lowercase();
    address.starts_with(token)
        || name.starts_with(token)
        || name.split_whitespace().any(|w| w.starts_with(token))
        || address
            .split_once('@')
            .is_some_and(|(_, domain)| domain.starts_with(token))
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

#[derive(Default)]
struct State {
    book: Book,
    /// Where the book is kept, once what it kept has been read into `book`.
    store: Option<Arc<Store>>,
    /// The account's own addresses, lowercase.
    me: Vec<String>,
}

/// What one account's connection knows of the people it writes with. Shared by the
/// threads that use the connection; the store's record is only ever written from here.
pub struct Contacts {
    state: Mutex<State>,
}

impl Contacts {
    fn new(email: &str) -> Self {
        let me = Some(email.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .into_iter()
            .collect();
        Self {
            state: Mutex::new(State {
                me,
                ..State::default()
            }),
        }
    }

    fn add_me(&self, address: &str) {
        let address = address.trim().to_lowercase();
        let mut state = self.state.lock().unwrap();
        if !address.is_empty() && !state.me.contains(&address) {
            state.book.people.remove(&address);
            state.me.push(address);
        }
    }

    /// Reads what the store keeps (the first time) and keeps the book there from now on.
    /// A store taken up again (the account shown again) is not read again: the book has
    /// all it had, and more. Blocking.
    fn attach(&self, store: &Arc<Store>) {
        if self.state.lock().unwrap().store.is_some() {
            self.state.lock().unwrap().store = Some(store.clone());
            return;
        }
        let mut saved: Book = store.load(KEY).unwrap_or_default();
        let mut state = self.state.lock().unwrap();
        if state.store.is_some() {
            state.store = Some(store.clone());
            return;
        }
        // Anything learnt before the store was open joins what it kept.
        let learnt = !state.book.people.is_empty();
        saved.merge(&state.book);
        state.book = saved;
        state.store = Some(store.clone());
        if learnt {
            Self::save(&state);
        }
    }

    /// Hands the book to the store's writer, once there is one. Until then the book is
    /// only what was learnt since launch, and `attach` adds it to what is kept.
    fn save(state: &State) {
        if let Some(store) = &state.store {
            store.save_soon(KEY, state.book.clone());
        }
    }

    /// Forgets everyone (the mail kept on this Mac was cleared), in the store too: Settings
    /// › Privacy clears only the shown account's store, and this is every account's.
    fn forget(&self) {
        let mut state = self.state.lock().unwrap();
        state.book = Book::default();
        Self::save(&state);
    }

    pub fn learn(&self, mets: &[Met]) {
        if mets.is_empty() {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let State { book, me, .. } = &mut *state;
        let mut changed = false;
        for met in mets {
            changed |= book.learn(met, me);
        }
        if changed {
            book.prune(now_ms());
            Self::save(&state);
        }
    }

    /// The people who match what is being typed (`token`, lowercase), best first, with
    /// their scores.
    pub fn suggest(&self, token: &str) -> Vec<(Person, f64)> {
        let now = now_ms();
        let state = self.state.lock().unwrap();
        let mut found: Vec<(Person, f64)> = state
            .book
            .people
            .iter()
            .map(|(address, known)| {
                let person = Person {
                    name: known.name.clone(),
                    address: address.clone(),
                };
                (person, known)
            })
            .filter(|(person, known)| {
                matches(person, token) && (!known.sent.is_empty() || !automated(&person.address))
            })
            .map(|(person, known)| {
                let score = known.score(now);
                (person, score)
            })
            .collect();
        found.sort_by(|a, b| {
            b.1.total_cmp(&a.1)
                .then_with(|| a.0.address.cmp(&b.0.address))
        });
        found.truncate(SHOWN * 4);
        found
    }

    /// One page of the first look through the account's newest sent, then received, mail.
    /// Says whether there is more to read. Blocking, and a network request: off the main
    /// thread, and paced by the caller (`SCAN_PAUSE`).
    pub fn scan_step(&self, client: &Client) -> Result<bool> {
        let (sent, page) = {
            let state = self.state.lock().unwrap();
            if state.store.is_none() {
                return Ok(false);
            }
            let book = &state.book;
            if !book.sent_scan.done {
                (true, book.sent_scan.next.clone())
            } else if !book.received_scan.done {
                (false, book.received_scan.next.clone())
            } else {
                return Ok(false);
            }
        };
        let (mets, next) = client.people_page(sent, page.as_deref())?;
        let mut state = self.state.lock().unwrap();
        let State { book, me, .. } = &mut *state;
        for met in &mets {
            book.learn(met, me);
        }
        book.prune(now_ms());
        let (scan, most) = if sent {
            (&mut book.sent_scan, SENT_MOST)
        } else {
            (&mut book.received_scan, RECEIVED_MOST)
        };
        scan.taken += mets.len();
        scan.done = next.is_none() || scan.taken >= most;
        scan.next = next;
        let more = !(book.sent_scan.done && book.received_scan.done);
        Self::save(&state);
        Ok(more)
    }
}

/// The people of a message just sent from the account.
fn sent_met(outgoing: &Outgoing) -> Met {
    let mut cc = mail::people(&outgoing.cc);
    cc.extend(mail::people(&outgoing.bcc));
    Met {
        from: Person::default(),
        to: mail::people(&outgoing.to),
        cc,
        timestamp_ms: now_ms(),
        sent: true,
    }
}

fn thread_mets(messages: &[Message]) -> Vec<Met> {
    messages
        .iter()
        .map(|m| Met {
            from: m.from.clone(),
            to: m.to.clone(),
            cc: m.cc.clone(),
            timestamp_ms: m.timestamp_ms,
            sent: false,
        })
        .collect()
}

/// A connection that learns the people of the mail passing through it, and otherwise is
/// the connection it wraps. Every account's connection is one (see [`wrap`]), so each way
/// mail comes in (the list, a thread, search, a send) teaches it without saying so.
pub struct Learning<P> {
    inner: P,
    contacts: Arc<Contacts>,
}

/// The connection the app keeps for an account whose address is `email` (empty when not
/// known yet: its profile says).
pub fn wrap<P: Provider + 'static>(inner: P, email: &str) -> Arc<Client> {
    wrap_sharing(inner, Arc::new(Contacts::new(email)))
}

/// The same for a new sign-in to an account that has a connection: it carries on with
/// what that one learnt.
pub fn wrap_sharing<P: Provider + 'static>(inner: P, contacts: Arc<Contacts>) -> Arc<Client> {
    Arc::new(Learning { inner, contacts })
}

impl<P: Provider> Learning<P> {
    /// Learns from list rows: each message's people, but not a draft's (it was not sent).
    fn rows(&self, rows: &[Summary]) {
        let mets: Vec<Met> = rows
            .iter()
            .flat_map(|row| {
                row.people.iter().enumerate().filter_map(|(index, met)| {
                    let draft = row
                        .message_labels
                        .get(index)
                        .is_some_and(|labels| labels.iter().any(|l| l == "DRAFT"));
                    (!draft).then(|| met.clone())
                })
            })
            .collect();
        self.contacts.learn(&mets);
    }
}

impl<P: Provider> Provider for Learning<P> {
    fn profile(&self) -> Result<(String, String)> {
        let profile = self.inner.profile()?;
        self.contacts.add_me(&profile.0);
        Ok(profile)
    }
    fn profile_photo(&self) -> Result<Photo> {
        self.inner.profile_photo()
    }
    fn writes(&self) -> u64 {
        self.inner.writes()
    }
    fn forget_rows(&self) {
        self.inner.forget_rows();
        self.contacts.forget();
    }
    fn keep_rows_in(&self, store: &Arc<Store>) {
        self.inner.keep_rows_in(store);
        self.contacts.attach(store);
    }
    fn history(&self, start: &str) -> Result<Changes> {
        self.inner.history(start)
    }
    fn wait_for_change(&self, timeout: Duration) -> bool {
        self.inner.wait_for_change(timeout)
    }
    fn threads_page(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Summary>, Option<String>)> {
        let listed = self.inner.threads_page(view, label_id, limit, page)?;
        // Not the Spam folder's: whoever is in it is not someone to suggest.
        if view != View::Spam {
            self.rows(&listed.0);
        }
        Ok(listed)
    }
    fn page_after(
        &self,
        view: View,
        label_id: Option<&str>,
        count: usize,
    ) -> Result<Option<String>> {
        self.inner.page_after(view, label_id, count)
    }
    fn summary(&self, id: &str, recipient: bool) -> Result<Summary> {
        let row = self.inner.summary(id, recipient)?;
        if !row.labels.iter().any(|l| l == "SPAM") {
            self.rows(std::slice::from_ref(&row));
        }
        Ok(row)
    }
    fn thread(&self, id: &str) -> Result<Vec<Message>> {
        let messages = self.inner.thread(id)?;
        self.contacts.learn(&thread_mets(&messages));
        Ok(messages)
    }
    fn download(&self, message_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
        self.inner.download(message_id, attachment_id)
    }
    fn change(&self, id: &str, change: Change) -> Result<()> {
        self.inner.change(id, change)
    }
    fn draft_for_thread(&self, thread_id: &str) -> Result<Draft> {
        self.inner.draft_for_thread(thread_id)
    }
    fn save_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        self.inner.save_draft(id, outgoing)
    }
    fn send_draft(&self, id: &str, outgoing: &Outgoing) -> Result<()> {
        self.inner.send_draft(id, outgoing)?;
        self.contacts.learn(&[sent_met(outgoing)]);
        Ok(())
    }
    fn keep_as_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        self.inner.keep_as_draft(id, outgoing)
    }
    fn send_saved_draft(&self, id: &str) -> Result<()> {
        self.inner.send_saved_draft(id)
    }
    fn delete_draft(&self, id: &str) -> Result<()> {
        self.inner.delete_draft(id)
    }
    fn send_message(&self, outgoing: &Outgoing) -> Result<()> {
        self.inner.send_message(outgoing)?;
        self.contacts.learn(&[sent_met(outgoing)]);
        Ok(())
    }
    fn delete_thread(&self, id: &str) -> Result<()> {
        self.inner.delete_thread(id)
    }
    fn labels(&self) -> Result<Vec<Label>> {
        self.inner.labels()
    }
    fn create_label(&self, name: &str) -> Result<Label> {
        self.inner.create_label(name)
    }
    fn rename_label(&self, id: &str, name: &str) -> Result<()> {
        self.inner.rename_label(id, name)
    }
    fn delete_label(&self, id: &str) -> Result<()> {
        self.inner.delete_label(id)
    }
    fn add_label(&self, id: &str, label_id: &str) -> Result<()> {
        self.inner.add_label(id, label_id)
    }
    fn remove_label(&self, id: &str, label_id: &str) -> Result<()> {
        self.inner.remove_label(id, label_id)
    }
    fn relabel(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        self.inner.relabel(id, add, remove)
    }
    fn counts(&self, label_ids: &[String]) -> HashMap<String, (u32, u32)> {
        self.inner.counts(label_ids)
    }
    fn people_page(&self, sent: bool, page: Option<&str>) -> Result<(Vec<Met>, Option<String>)> {
        self.inner.people_page(sent, page)
    }
    fn contacts(&self) -> Option<&Arc<Contacts>> {
        Some(&self.contacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const DAY: i64 = 86_400_000;

    fn person(name: &str, address: &str) -> Person {
        Person {
            name: name.into(),
            address: address.into(),
        }
    }

    fn met(from: Person, to: &[Person], at: i64, sent: bool) -> Met {
        Met {
            from,
            to: to.to_vec(),
            cc: Vec::new(),
            timestamp_ms: at,
            sent,
        }
    }

    fn me() -> Person {
        person("Me", "me@example.com")
    }

    fn addresses(found: &[(Person, f64)]) -> Vec<&str> {
        found.iter().map(|(p, _)| p.address.as_str()).collect()
    }

    /// Pages of people, as a provider would hand them out; counts the requests.
    #[derive(Default)]
    struct Fake {
        sent: Vec<Vec<Met>>,
        received: Vec<Vec<Met>>,
        asked: AtomicUsize,
        fail: bool,
    }

    impl Fake {
        fn page(&self, pages: &[Vec<Met>], page: Option<&str>) -> (Vec<Met>, Option<String>) {
            let at: usize = page.map_or(0, |p| p.parse().unwrap());
            let next = (at + 1 < pages.len()).then(|| (at + 1).to_string());
            (pages.get(at).cloned().unwrap_or_default(), next)
        }
    }

    impl Provider for Fake {
        fn profile(&self) -> Result<(String, String)> {
            Ok(("me@example.com".into(), "1".into()))
        }
        fn writes(&self) -> u64 {
            0
        }
        fn forget_rows(&self) {}
        fn keep_rows_in(&self, _: &Arc<Store>) {}
        fn history(&self, _: &str) -> Result<Changes> {
            Ok(Changes::default())
        }
        fn threads_page(
            &self,
            _: View,
            _: Option<&str>,
            _: usize,
            _: Option<&str>,
        ) -> Result<(Vec<Summary>, Option<String>)> {
            Ok((vec![row()], None))
        }
        fn page_after(&self, _: View, _: Option<&str>, _: usize) -> Result<Option<String>> {
            Ok(None)
        }
        fn summary(&self, _: &str, _: bool) -> Result<Summary> {
            Ok(row())
        }
        fn thread(&self, _: &str) -> Result<Vec<Message>> {
            Ok(Vec::new())
        }
        fn download(&self, _: &str, _: &str) -> Result<Vec<u8>> {
            unimplemented!()
        }
        fn change(&self, _: &str, _: Change) -> Result<()> {
            Ok(())
        }
        fn draft_for_thread(&self, _: &str) -> Result<Draft> {
            unimplemented!()
        }
        fn save_draft(&self, _: Option<&str>, _: &Outgoing) -> Result<String> {
            Ok("d".into())
        }
        fn send_draft(&self, _: &str, _: &Outgoing) -> Result<()> {
            Ok(())
        }
        fn keep_as_draft(&self, _: Option<&str>, _: &Outgoing) -> Result<String> {
            Ok("d".into())
        }
        fn send_saved_draft(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn delete_draft(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn send_message(&self, _: &Outgoing) -> Result<()> {
            if self.fail {
                anyhow::bail!("not sent");
            }
            Ok(())
        }
        fn delete_thread(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn labels(&self) -> Result<Vec<Label>> {
            Ok(Vec::new())
        }
        fn create_label(&self, _: &str) -> Result<Label> {
            unimplemented!()
        }
        fn rename_label(&self, _: &str, _: &str) -> Result<()> {
            Ok(())
        }
        fn delete_label(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn add_label(&self, _: &str, _: &str) -> Result<()> {
            Ok(())
        }
        fn remove_label(&self, _: &str, _: &str) -> Result<()> {
            Ok(())
        }
        fn relabel(&self, _: &str, _: &[&str], _: &[&str]) -> Result<()> {
            Ok(())
        }
        fn counts(&self, _: &[String]) -> HashMap<String, (u32, u32)> {
            HashMap::new()
        }
        fn people_page(
            &self,
            sent: bool,
            page: Option<&str>,
        ) -> Result<(Vec<Met>, Option<String>)> {
            self.asked.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                anyhow::bail!("offline");
            }
            Ok(self.page(if sent { &self.sent } else { &self.received }, page))
        }
    }

    /// A thread of a message from Ana and a draft of a reply to Bo.
    fn row() -> Summary {
        Summary {
            id: "t".into(),
            sender: "Ana".into(),
            sender_address: String::new(),
            subject: String::new(),
            snippet: String::new(),
            timestamp_ms: 0,
            message_count: 2,
            unread: false,
            starred: false,
            labels: vec!["INBOX".into(), "DRAFT".into()],
            message_labels: vec![vec!["INBOX".into()], vec!["DRAFT".into()]],
            senders: Vec::new(),
            people: vec![
                met(
                    person("Ana Lima", "ana@example.com"),
                    &[me()],
                    10 * DAY,
                    false,
                ),
                met(me(), &[person("Bo", "bo@example.com")], 11 * DAY, false),
            ],
        }
    }

    fn contacts_of(client: &Client) -> &Contacts {
        client.contacts().unwrap()
    }

    #[test]
    fn learning_the_same_mail_again_changes_nothing() {
        let mut book = Book::default();
        let me = vec!["me@example.com".to_string()];
        let mail = met(person("Ana", "ana@example.com"), &[me_person()], 5, false);
        assert!(book.learn(&mail, &me));
        assert!(!book.learn(&mail, &me), "listed again: nothing to save");
        assert_eq!(book.people["ana@example.com"].seen, vec![5]);
    }

    fn me_person() -> Person {
        me()
    }

    #[test]
    fn suggestions_across_accounts_favour_the_one_written_from_and_skip_mine_and_present() {
        let now = now_ms();
        let work = Contacts::new("me@example.com");
        work.learn(&[met(
            me(),
            &[person("Sam Work", "sam@work.example")],
            now,
            true,
        )]);
        let home = Contacts::new("me@home.example");
        home.learn(&[
            met(
                person("Me", "me@home.example"),
                &[person("Sam Home", "sam@home.example")],
                now,
                true,
            ),
            met(
                person("Me", "me@home.example"),
                &[person("Sara", "sara@home.example")],
                now,
                true,
            ),
        ]);
        let seen = [person("Sam Seen", "sam@seen.example"), me()];
        let mine = ["me@example.com".to_string(), "me@home.example".to_string()];
        let present = ["sara@home.example".to_string()];
        let found = rank(
            "sa",
            "home",
            [("work", &work), ("home", &home)],
            seen.iter(),
            &mine,
            &present,
        );
        let addresses: Vec<&str> = found.iter().map(|p| p.address.as_str()).collect();
        assert_eq!(
            addresses[0], "sam@home.example",
            "the account written from counts double"
        );
        assert!(addresses.contains(&"sam@work.example") && addresses.contains(&"sam@seen.example"));
        assert!(
            !addresses.contains(&"sara@home.example") && !addresses.contains(&"me@example.com")
        );
    }

    #[test]
    fn people_written_to_come_before_people_only_heard_from() {
        let contacts = Contacts::new("me@example.com");
        let now = now_ms();
        contacts.learn(&[
            met(
                person("Sam Heard", "sam.heard@example.com"),
                &[me()],
                now,
                false,
            ),
            met(
                me(),
                &[person("Sam Wrote", "sam.wrote@example.com")],
                now - DAY,
                false,
            ),
        ]);
        let found = contacts.suggest("sam");
        assert_eq!(
            addresses(&found),
            ["sam.wrote@example.com", "sam.heard@example.com"]
        );
    }

    #[test]
    fn recent_mail_counts_for_more_than_old() {
        let contacts = Contacts::new("me@example.com");
        let now = now_ms();
        contacts.learn(&[
            met(
                me(),
                &[person("", "old@example.com")],
                now - 400 * DAY,
                true,
            ),
            met(me(), &[person("", "new@example.com")], now - DAY, true),
        ]);
        assert_eq!(
            addresses(&contacts.suggest("")),
            Vec::<&str>::new(),
            "nothing typed, nothing suggested"
        );
        let found = contacts.suggest("example");
        assert_eq!(addresses(&found), ["new@example.com", "old@example.com"]);
    }

    #[test]
    fn matches_the_address_a_word_of_the_name_and_the_domain() {
        let ana = person("Ana Maria Lima", "a.lima@acme.example");
        for token in ["a.li", "ana", "maria", "lima", "acme"] {
            assert!(matches(&ana, token), "{token}");
        }
        for token in ["ima", "example", "x"] {
            assert!(!matches(&ana, token), "{token}");
        }
    }

    #[test]
    fn the_users_own_addresses_are_never_suggested() {
        let contacts = Contacts::new("");
        let mail = met(person("Ana", "ana@example.com"), &[me()], 1, false);
        contacts.learn(&[mail]);
        assert!(addresses(&contacts.suggest("me")).contains(&"me@example.com"));
        // Its profile says whose the account is: that address goes.
        contacts.add_me("Me@Example.com");
        assert!(contacts.suggest("me").is_empty());
        contacts.learn(&[met(me(), &[person("Bo", "bo@example.com")], 2, false)]);
        assert_eq!(addresses(&contacts.suggest("bo")), ["bo@example.com"]);
        assert!(
            contacts.state.lock().unwrap().book.people["bo@example.com"].sent == vec![2],
            "mail from the user's own address is mail the user sent"
        );
    }

    #[test]
    fn machines_are_left_out_unless_written_to() {
        let contacts = Contacts::new("me@example.com");
        contacts.learn(&[
            met(person("Shop", "no-reply@shop.example"), &[me()], 1, false),
            met(
                person("Alerts", "notifications@bank.example"),
                &[me()],
                1,
                false,
            ),
        ]);
        assert!(contacts.suggest("no").is_empty());
        assert!(contacts.suggest("shop").is_empty());
        contacts.learn(&[met(me(), &[person("", "noreply@help.example")], 2, true)]);
        assert_eq!(
            addresses(&contacts.suggest("help")),
            ["noreply@help.example"]
        );
    }

    #[test]
    fn the_newest_name_wins_and_an_empty_one_never_replaces_it() {
        let mut book = Book::default();
        let me = vec!["me@example.com".to_string()];
        book.learn(
            &met(person("Ana", "ana@example.com"), &[me_person()], 5, false),
            &me,
        );
        book.learn(
            &met(
                person("Ana Lima", "ana@example.com"),
                &[me_person()],
                9,
                false,
            ),
            &me,
        );
        book.learn(
            &met(person("A.", "ana@example.com"), &[me_person()], 1, false),
            &me,
        );
        book.learn(
            &met(person("", "ana@example.com"), &[me_person()], 20, false),
            &me,
        );
        assert_eq!(book.people["ana@example.com"].name, "Ana Lima");
    }

    #[test]
    fn names_are_one_line_and_never_the_address_again() {
        assert_eq!(
            clean_name("Ana\r\n  Lima\u{7}", "a@example.com"),
            "Ana Lima"
        );
        assert_eq!(clean_name("A@Example.com", "a@example.com"), "");
        assert_eq!(
            clean_name(&"x".repeat(500), "a@example.com").len(),
            NAME_MOST
        );
    }

    #[test]
    fn invalid_addresses_are_not_kept() {
        let contacts = Contacts::new("me@example.com");
        contacts.learn(&[met(person("Nobody", "not an address"), &[me()], 1, false)]);
        assert!(contacts.state.lock().unwrap().book.people.is_empty());
    }

    #[test]
    fn only_the_newest_times_are_kept() {
        let mut known = Known::default();
        for at in 0..20 {
            known.note("", Kind::Seen, at);
        }
        assert_eq!(known.seen, (12..20).rev().collect::<Vec<_>>());
        assert!(
            !known.note("", Kind::Seen, 3),
            "older than all kept: nothing changes"
        );
    }

    #[test]
    fn the_book_keeps_to_its_size_dropping_the_least_wanted() {
        let mut book = Book::default();
        let me = vec!["me@example.com".to_string()];
        let now = now_ms();
        for i in 0..MOST_PEOPLE {
            let mail = met(
                person("", &format!("p{i}@example.com")),
                &[me_person()],
                now - DAY,
                false,
            );
            book.learn(&mail, &me);
        }
        for i in 0..10 {
            let mail = met(
                person("", &format!("old{i}@example.com")),
                &[me_person()],
                now - 900 * DAY,
                false,
            );
            book.learn(&mail, &me);
        }
        book.prune(now);
        assert_eq!(book.people.len(), MOST_PEOPLE);
        assert!(!book.people.keys().any(|a| a.starts_with("old")));
    }

    #[test]
    fn rows_teach_their_people_but_not_their_drafts() {
        let client = wrap(Fake::default(), "me@example.com");
        client.threads_page(View::Inbox, None, 30, None).unwrap();
        let contacts = contacts_of(&*client);
        assert_eq!(addresses(&contacts.suggest("ana")), ["ana@example.com"]);
        assert!(
            contacts.suggest("bo").is_empty(),
            "a draft was not sent to anyone"
        );
        // Nothing from Spam.
        let spam = wrap(Fake::default(), "me@example.com");
        spam.threads_page(View::Spam, None, 30, None).unwrap();
        assert!(contacts_of(&*spam).suggest("ana").is_empty());
    }

    #[test]
    fn a_message_sent_teaches_its_recipients_and_one_that_failed_does_not() {
        let outgoing = Outgoing {
            to: "\"Lima, Ana\" <ana@example.com>, bo@example.com".into(),
            cc: "Cy <cy@example.com>".into(),
            bcc: "dee@example.com".into(),
            ..Outgoing::default()
        };
        let client = wrap(Fake::default(), "me@example.com");
        client.send_message(&outgoing).unwrap();
        let contacts = contacts_of(&*client);
        for (token, address) in [
            ("lima", "ana@example.com"),
            ("bo", "bo@example.com"),
            ("cy", "cy@example.com"),
            ("dee", "dee@example.com"),
        ] {
            assert_eq!(addresses(&contacts.suggest(token)), [address]);
        }
        let failing = wrap(
            Fake {
                fail: true,
                ..Fake::default()
            },
            "me@example.com",
        );
        assert!(failing.send_message(&outgoing).is_err());
        assert!(contacts_of(&*failing).suggest("bo").is_empty());
    }

    #[test]
    fn what_is_learnt_is_kept_in_the_store_and_read_back() {
        let store = Arc::new(Store::temp());
        let client = wrap(Fake::default(), "me@example.com");
        // Learnt before the store was open: joins what it keeps.
        client.threads_page(View::Inbox, None, 30, None).unwrap();
        client.keep_rows_in(&store);
        crate::store::flush_store(&store, std::time::Instant::now() + Duration::from_secs(5));
        let again = wrap(Fake::default(), "me@example.com");
        again.keep_rows_in(&store);
        assert_eq!(
            addresses(&contacts_of(&*again).suggest("ana")),
            ["ana@example.com"]
        );
    }

    #[test]
    fn the_store_taken_up_again_is_not_read_over_what_was_learnt() {
        let store = Arc::new(Store::temp());
        let client = wrap(Fake::default(), "me@example.com");
        client.keep_rows_in(&store);
        crate::store::flush_store(&store, std::time::Instant::now() + Duration::from_secs(5));
        client
            .send_message(&Outgoing {
                to: "new@example.com".into(),
                ..Outgoing::default()
            })
            .unwrap();
        // Shown again before the writer saved the send: the book stays as it is.
        let later = Store::temp_like(&store);
        client.keep_rows_in(&Arc::new(later));
        assert_eq!(
            addresses(&contacts_of(&*client).suggest("new")),
            ["new@example.com"]
        );
    }

    #[test]
    fn the_first_look_reads_sent_then_received_and_remembers_where_it_got_to() {
        let now = now_ms();
        let fake = Fake {
            sent: vec![
                vec![met(me(), &[person("", "s1@example.com")], now, true)],
                vec![met(me(), &[person("", "s2@example.com")], now, true)],
            ],
            received: vec![vec![met(person("", "r1@example.com"), &[me()], now, false)]],
            ..Fake::default()
        };
        let client = wrap(fake, "me@example.com");
        let contacts = contacts_of(&*client);
        assert!(
            !contacts.scan_step(&*client).unwrap(),
            "no store: nothing to keep it in"
        );
        let store = Arc::new(Store::temp());
        client.keep_rows_in(&store);
        assert!(contacts.scan_step(&*client).unwrap());
        assert!(
            contacts.scan_step(&*client).unwrap(),
            "Sent done, the inbox next"
        );
        assert!(!contacts.scan_step(&*client).unwrap(), "all read");
        assert!(!contacts.scan_step(&*client).unwrap());
        for token in ["s1", "s2", "r1"] {
            assert_eq!(contacts.suggest(token).len(), 1, "{token}");
        }
        crate::store::flush_store(&store, std::time::Instant::now() + Duration::from_secs(5));
        // Read again later: done, and not asked again.
        let again = wrap(
            Fake {
                fail: true,
                ..Fake::default()
            },
            "me@example.com",
        );
        again.keep_rows_in(&store);
        assert!(!contacts_of(&*again).scan_step(&*again).unwrap());
    }

    #[test]
    fn the_first_look_stops_at_its_limit() {
        let now = now_ms();
        let page: Vec<Met> = (0..SENT_MOST / 2)
            .map(|i| {
                met(
                    me(),
                    &[person("", &format!("s{i}@example.com"))],
                    now - i as i64,
                    true,
                )
            })
            .collect();
        let fake = Fake {
            sent: vec![page; 5],
            ..Fake::default()
        };
        let client = wrap(fake, "me@example.com");
        client.keep_rows_in(&Arc::new(Store::temp()));
        let contacts = contacts_of(&*client);
        while contacts.scan_step(&*client).unwrap() {}
        let state = contacts.state.lock().unwrap();
        assert!(state.book.sent_scan.done);
        assert_eq!(state.book.sent_scan.taken, SENT_MOST, "two pages of five");
    }

    #[test]
    fn a_failing_first_look_says_so_and_keeps_its_place() {
        let client = wrap(
            Fake {
                fail: true,
                ..Fake::default()
            },
            "me@example.com",
        );
        client.keep_rows_in(&Arc::new(Store::temp()));
        let contacts = contacts_of(&*client);
        assert!(contacts.scan_step(&*client).is_err());
        assert!(!contacts.state.lock().unwrap().book.sent_scan.done);
    }

    #[test]
    fn clearing_the_mail_kept_forgets_the_people_too() {
        let store = Arc::new(Store::temp());
        let client = wrap(Fake::default(), "me@example.com");
        client.keep_rows_in(&store);
        client.threads_page(View::Inbox, None, 30, None).unwrap();
        client.forget_rows();
        assert!(contacts_of(&*client).suggest("ana").is_empty());
        crate::store::flush_store(&store, std::time::Instant::now() + Duration::from_secs(5));
        let again = wrap(Fake::default(), "me@example.com");
        again.keep_rows_in(&store);
        assert!(
            contacts_of(&*again).suggest("ana").is_empty(),
            "nor back after a relaunch"
        );
    }

    #[test]
    fn a_new_sign_in_carries_on_with_what_was_learnt() {
        let client = wrap(Fake::default(), "me@example.com");
        client.threads_page(View::Inbox, None, 30, None).unwrap();
        let again = wrap_sharing(Fake::default(), client.contacts().unwrap().clone());
        assert_eq!(
            addresses(&contacts_of(&*again).suggest("ana")),
            ["ana@example.com"]
        );
    }
}
