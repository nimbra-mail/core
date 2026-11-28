# nimbra-core

Nimbra's mail engine, without any UI: Gmail, Microsoft and IMAP/SMTP accounts, MIME, server discovery, the
encrypted on-device store, sending (undo send and send later), snooze and reminders, blocked senders, address
suggestions, brand logos (BIMI), signatures and preferences. Both Nimbra apps run it: the macOS app ([desktop](https://github.com/nimbra-mail/desktop))
as a Rust crate, and the iOS app ([ios](https://github.com/nimbra-mail/ios)) as a Swift package.

Private by default: mail and sign-ins stay on the device. Secrets live only in the Keychain, the store is encrypted
with a key kept there, and nothing secret is logged or put into an error.

## Layout

| Path | What |
| --- | --- |
| `crates/nimbra-core` | The engine. `mail.rs` is the model and the `Provider` interface; `gmail.rs`, `microsoft.rs`, `imap_mail.rs`, `smtp.rs` and `tls.rs` the providers; `store.rs` the encrypted store and `listing.rs` the mailboxes kept in it (rows, change-feed sync, All inboxes, the Split Inbox, labels); `snooze.rs`, `outbox.rs`, `sending.rs`, `scheduled.rs` and `leaving.rs` snooze, the offline queue and sending; `composing.rs` the HTML sent and replies; `bimi.rs` brand logos for senders that pass DMARC; `settings.rs` the preferences both apps share; `accounts.rs`, `notifying.rs`, `watching.rs` and `contacts.rs` accounts, notifications and the badge, live updates and address suggestions; `oauth.rs` a sign-in that comes back to an app's own redirect; `paths.rs` where an app other than the Mac's keeps its files. Its `lib.rs` lists them all. |
| `crates/nimbra-ffi` | The engine for Swift, through [UniFFI](https://mozilla.github.io/uniffi-rs): one `Engine` object, a `SecretStore` the app implements, and a few free functions. |
| `Package.swift`, `Sources/NimbraCore` | The Swift package iOS uses: the generated Swift API (kept in git, never edited by hand) over `NimbraFFI.xcframework`. |
| `scripts/build-ios-core.sh` | Builds the XCFramework (iPhone and Apple silicon simulator) and generates the Swift API. |
| `scripts/release` | Releases a version: checks, the XCFramework zip, `Package.swift`, the tag and the GitHub Release. |
| `docs/testing.md` | The live IMAP and SMTP tests against local servers. |
| `CHANGELOG.md`, `docs/releasing.md` | What changed in each version, and how a release is made. |

## Checking a change

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

Tests use sample data and `example.com` addresses. They never touch the network, a real mailbox, the Keychain or
the Mac app's own folders.

## How the apps use it

Both apps use a published release, and both have `scripts/local-core.sh` to build against a checkout of this repo
next to them (`../core`) while trying a change: `on` switches to it, `off` goes back to the release (run it before
committing there), and `status` says which one is in use.

**macOS** ([desktop](https://github.com/nimbra-mail/desktop)) depends on the crate by its release tag, in
`Cargo.toml`:

```toml
nimbra-core = { git = "https://github.com/nimbra-mail/core", tag = "v0.1.7" }
```

The app brings the modules in by name (`use nimbra_core::{mail, gmail, …}`), so its code reads `crate::mail` as
before. The `test-support` feature gives the app's own tests temporary stores. The Mac app keeps its folders where
they have always been (`~/Library/Application Support/Nimbra`).

**iOS** ([ios](https://github.com/nimbra-mail/ios)) depends on the Swift package by this repo's URL, in
`project.yml`; SwiftPM takes the release's XCFramework by URL and checksum, without building Rust:

```yaml
packages:
  NimbraCore:
    url: https://github.com/nimbra-mail/core
    exactVersion: 0.1.7
```

In Swift:

```swift
import NimbraCore

let engine = try Engine(
    config: EngineConfig(googleClientId: googleId, googleClientSecret: nil, microsoftClientId: microsoftId),
    dataDir: applicationSupport.path,   // the app's own folders: there is no default
    cacheDir: caches.path,
    secrets: KeychainSecretStore()      // the app's Keychain, after first unlock, this device only
)
```

Every `Engine` method blocks (network, disk or Keychain): call it from a background task, never the main actor.
The generated types are `Sendable`. Sign-in runs in `ASWebAuthenticationSession`: `beginGoogleSignIn` (or
`beginMicrosoftSignIn`) gives the authorize URL (PKCE) for the app's custom-scheme redirect, and
`finishGoogleSignIn` takes the address the session came back to. An iOS Google client has no secret, and client
ids are passed in, never built in.

The Swift API, by area (each `Engine` method says in its doc whether it goes to the network):

| Area | Calls |
| --- | --- |
| Setup | `Engine(config:dataDir:cacheDir:secrets:)`, `flush`, `useDnsResolver` (MX and TXT lookups through the system on iOS), `coreVersion` |
| Accounts | `accounts`, `setDefaultAccount`, `moveAccount`, `accountPhoto`, `keptAccountPhoto`, `begin`/`finishGoogleSignIn`, `begin`/`finishMicrosoftSignIn`, `cancelSignIn`, `knownServers`, `discoverServers`, `addImapAccount`, `updateImapPassword`, `removeAccount`, `isEmailAddress` |
| Mailboxes | `mailboxes`, `cachedThreads`, `refreshMailbox`, `loadMore`, `cachedAllInboxes`, `allInboxes`, `cachedEveryMailbox`, `everyMailbox`, `search`, `labels`, `counts`, `cachedCounts` |
| Reading | `readThread`, `cachedThread`, `brandLogo`, `downloadAttachment`, `fetchRemoteImage`, `parseMailto`, `unsubscribeAction` |
| Actions | `apply` (queued when offline), `undoAction`, `moveToInbox`, `moveToLabel`, `relabel`, label CRUD, `deleteThread`, `blockSender`, `unblockSender`, `blockedSenders` |
| Snooze | `snooze`, `snoozed`, `unsnooze`, `wakeDue`, `snoozeTimes`, `parseTime`, `dayTime` |
| Writing | `startAnswer`, `messageHtml`, `splitDraftHtml`, `textToHtml`, `saveDraft`, `saveToDrafts`, `draftForThread`, `deleteDraft`, `queueSend` then `OutgoingSend.deliver`/`undo`, `unsent`, `catchUp`, `scheduleSend`, `scheduledSends`, `cancelScheduled`, `sendDue`, `sendLaterTimes`, `suggestContacts`, `learnContacts` |
| Signatures | `signatures`, `addSignature`, `updateSignature`, `deleteSignature`, `setDefaultSignature` |
| Preferences | `preferences`, `setPreferences` (the shared `Settings`), `clearKeptMail` |
| Staying current | `checkForChanges` (what to notify about), `watch` (`ChangeWatch`), `checkIntervalSeconds`, `pendingWork` (the next deadline for a timer or background task), `badgeCount`, `markReadAfterMs` |

## Building for iOS

Needs Xcode and rustup with the iOS targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim   # once
./scripts/build-ios-core.sh
```

This writes `NimbraFFI.xcframework` (not in git) and `Sources/NimbraCore/NimbraCore.swift` (in git, so a change to
the API shows in review: commit it with the Rust change). `Package.swift` uses the local XCFramework when it is
there.

## Releasing

`./scripts/release <version>` checks the engine, builds the XCFramework zip, points `Package.swift` at it, tags the
version and publishes the GitHub Release with the [CHANGELOG.md](CHANGELOG.md) section as its notes. A release carries
the XCFramework, so that iOS can depend on the package by URL and checksum without building Rust.
[docs/releasing.md](docs/releasing.md) has the details.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has how to work on it and the commit style
([Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)). Found a security problem? Report it
privately: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
