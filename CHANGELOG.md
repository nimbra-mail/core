# nimbra-core changelog

Changes to the mail engine (the `nimbra-core` crate) and its Swift API (the `NimbraCore` package). The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org): while on 0.x, a minor version may break the crate or the Swift API, and every such change is marked **Breaking**.

## [Unreleased]

### Breaking
- `Discovery` has a new case, `google(servers:)`, for gmail.com, googlemail.com and any domain whose mail Google runs (they were `needsOAuth(provider: "Google")`). Continue with Google stays the way in; `servers` are Gmail's (`imap.gmail.com` 993 and `smtp.gmail.com` 465, TLS, the full address as the user name) for adding the account with `addImapAccount` and an app password. `needsOAuth` is now Microsoft's or another provider's only. In the crate, `discover::Found::Google(Servers)`.
- `NimbraError` has a new case, `NeedsAppPassword(accountId:)`: as `SignedOut`, when Gmail refused the Google account's own password because, with 2-Step Verification on, it takes only an app password. A `switch` on `NimbraError` covers it.

### Added
- In the crate: `servers::gmail(email)`, `Servers::is_gmail()`, `Servers::normalize_password(typed)` (control characters around a password, such as a line break or tab, go; a Google app password loses the spaces Google shows it with, and no other provider's password loses any) and `mail::NeedsAppPassword`, next to `mail::SignedOut` from IMAP and `smtp::AuthFailed` from SMTP. `addImapAccount` and `updateImapPassword` normalize the password before checking and keeping it.

### Fixed
- Two `addImapAccount` (or sign-in) calls for the same address at once no longer both keep it: the second is refused as already here and its saved sign-in forgotten.
- Gmail over IMAP: Important (`\Important`) is no longer listed as a label, as All Mail and Starred are not, and a message sent through Gmail is not filed in Sent again (Gmail files it itself).

## [0.1.3] - 2026-11-27

### Breaking
- `TextSize` has a new variant, `ExtraLarge`: a `match` on it covers that too.
- `Summary` has a new field, `brand_domain`: code that builds a `Summary` sets it too (`None` when unknown).
- `Meta` has a new field, `rows` (the rows' format, `listing::ROWS`): code that builds a `Meta` field by field sets it too.
- `Settings` has a new field, `interface_zoom`: code that builds a `Settings` field by field sets it too (or uses `..Settings::default()`).

### Added
- Brand logos (BIMI): `bimi::logo(store, domain)` gives a domain's logo (an SVG, at most 32 KB, kept in the store for a week) when its DMARC policy is enforced and its BIMI record names one; `Summary::brand_domain` and `Row::brand_domain` say whose logo may stand for the sender (the latest message passed DMARC for that domain, by the receiving server's own Authentication-Results); `mail::dmarc_domain`; `dns::txt`, and `Resolver::txt` (an app's resolver may answer TXT; by default it doesn't).
- `Store::open_shared(name)`: an app-wide store, no account's, encrypted with its own key; the Mac app keeps brand logos there, once for every account.
- `TextSize::ExtraLarge` (saved as `"extralarge"`): 19pt text on 32pt lines in the reader.
- `Settings::interface_zoom` (percent, saved as `interface_zoom`, 100 when missing) and `Settings::zoom()`, which keeps it to one of `ZOOM_STEPS` (90, 100, 110, 125): how large the whole interface is drawn.

## [0.1.2] - 2026-11-27

### Breaking
- In the crate, `View::AllInboxes` is now `View::ALL_INBOXES`, one of the new `View::Every` mailboxes (see Added). A `match` on `View` covers `View::Every(_)`.

### Added
- Every account's mailbox, not just the inbox: `Engine.everyMailbox(mailbox:perAccount:)` and `cachedEveryMailbox(mailbox:)` list one mailbox (Trash, Sent, Drafts, Primary…) of every account together, newest first, as `allInboxes` lists the inbox (which now calls them). Gmail's own mailboxes (the Split Inbox categories and Important) leave out the accounts with their own servers; a label is refused (labels are each account's own). `AllInboxesPage.unread` is each account's count of that mailbox: unread threads, or every draft for Drafts. Network / disk.
- In the crate: `View::Every`, `View::every`, `View::base`, `View::gmail_only`, `View::number`; `listing::account_view`, `takes_part`, `count_of`, `mailbox_count`, and `labels_by_name` (every account's labels, one per name).

## [0.1.1] - 2026-11-27

### Breaking
- `NimbraError.SignedOut(account:)` is now `SignedOut(accountId: String?)`: always an account id on this device, or `nil` when the address being added (`addImapAccount`, a new account's `finish…SignIn`) did not take the password or sign-in. It was an empty string there before. A refused SMTP password while adding is now `SignedOut` too, not `Failed`. Match on `accountId` instead of `account`.
- `ThreadRow` has a new field, `senderAddress` (see Added): code that builds a `ThreadRow` itself (previews, tests) passes it. In the crate, so does code that builds a `mail::Summary` (`sender_address`).

### Added
- `Engine.updateImapPassword(accountId:password:)`: signs in to an account with its own servers again with a new password, checked with its IMAP and SMTP servers as adding one is. The account keeps its id, its stored mail and its signatures; a refused password is `SignedOut` for that account and leaves the old one. Network.
- `ThreadRow.senderAddress`: the address of whoever `sender` names (the latest message's sender, or in Sent and Drafts its first recipient), so an avatar's tone and a quick reply are right before the thread is read. `nil` when there is none, and for rows kept by 0.1.0 until their thread changes. In the crate: `Summary::sender_address` and `Row::sender_address`.
- `accounts::check_password` in the crate: both servers' check that adding an account and a new password share.

### Fixed
- After a change-feed sync, `refreshMailbox`'s `nextPage` started after as many threads as were listed before the changes, so `loadMore` skipped a thread for each one that left the list. It now starts right after the threads returned, and nothing is kept if finding it fails.

## [0.1.0] - 2026-11-26

The first release: the engine the macOS app ran, split out of it so the iOS app can run it too.

### Added
- **The engine as its own crate,** moved out of the desktop app with its history and its tests, and no UI:
  - Providers: Gmail (with incremental sync from its change feed), Microsoft, and any IMAP and SMTP server (IDLE for live updates), behind one `Provider` interface, with TLS through rustls and certificates always checked.
  - MIME parsing of untrusted mail with limits, and HTML or text as styled blocks.
  - Server discovery: well-known providers, MX records (custom domains at Google, Microsoft or Zoho), and the usual host names when a domain publishes nothing.
  - The encrypted on-disk store, with its key in the Keychain.
  - Sending with undo send and send later, snooze and reminders ("only if nobody replies"), signatures per account, address suggestions, labels, blocked senders, email links and preferences.
- **The logic both apps share,** moved from the Mac app into the engine: the listing cache and offline mailboxes, All inboxes, the Split Inbox lists, the outbox (the offline queue and what quitting has to finish), the HTML sent and what a reply or forward starts with, accounts, live updates, the rules for notifications, the badge and mark-read timing, and contact ranking.
- **The `NimbraCore` Swift package** (`crates/nimbra-ffi`, through UniFFI):
  - One `Engine` for accounts and sign-in, mailboxes, reading, actions, snooze, drafts, sending, contacts, signatures and preferences. Every method blocks, and its doc says whether it goes to the network.
  - `SecretStore`, which the app implements: every secret (refresh tokens, passwords, the store's key) goes to the app's Keychain with the accessibility it chooses.
  - `DnsResolver`, which the app implements (`useDnsResolver`): discovery's MX lookups go through the system's resolver, since the iOS sandbox has none of its own.
  - The app's own data and cache folders, passed to `Engine`, with no default.
  - Sign-in through the app's own redirect (`begin`/`finishGoogleSignIn`, `begin`/`finishMicrosoftSignIn`, with PKCE): the app runs `ASWebAuthenticationSession` and passes in its client ids, as nothing is built in for iOS.
  - `NimbraFFI.xcframework` for iPhone and the Apple silicon simulator, attached to the release, so the package resolves by URL and checksum without building Rust.
