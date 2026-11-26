# nimbra-core changelog

Changes to the mail engine (the `nimbra-core` crate) and its Swift API (the `NimbraCore` package). The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org): while on 0.x, a minor version may break the crate or the Swift API, and every such change is marked **Breaking**.

## [Unreleased]

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
