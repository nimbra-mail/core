# nimbra-core

Nimbra's mail engine, without any UI: Gmail, Microsoft and IMAP/SMTP accounts, MIME, server discovery, the
encrypted on-device store, sending (undo send and send later), snooze and reminders, blocked senders, address
suggestions, signatures and preferences. Both Nimbra apps run it: the macOS app ([desktop](https://github.com/nimbra-mail/desktop))
as a Rust crate, and the iOS app ([ios](https://github.com/nimbra-mail/ios)) as a Swift package.

Private by default: mail and sign-ins stay on the device. Secrets live only in the Keychain, the store is encrypted
with a key kept there, and nothing secret is logged or put into an error.

## Layout

| Path | What |
| --- | --- |
| `crates/nimbra-core` | The engine. `mail.rs` is the model and the `Provider` interface; `gmail.rs`, `microsoft.rs`, `imap_mail.rs`, `smtp.rs` and `tls.rs` the providers; `store.rs` the encrypted store; `oauth.rs` a sign-in that comes back to an app's own redirect; `paths.rs` where an app other than the Mac's keeps its files. Its `lib.rs` lists them all. |
| `crates/nimbra-ffi` | The engine for Swift, through [UniFFI](https://mozilla.github.io/uniffi-rs): one `Engine` object, a `SecretStore` the app implements, and a few free functions. |
| `Package.swift`, `Sources/NimbraCore` | The Swift package iOS uses: the generated Swift API (kept in git, never edited by hand) over `NimbraFFI.xcframework`. |
| `scripts/build-ios-core.sh` | Builds the XCFramework (iPhone and Apple silicon simulator) and generates the Swift API. |
| `docs/testing.md` | The live IMAP and SMTP tests against local servers. |

## Checking a change

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

Tests use sample data and `example.com` addresses. They never touch the network, a real mailbox, the Keychain or
the Mac app's own folders.

## How the apps use it

**macOS** ([desktop](https://github.com/nimbra-mail/desktop)) depends on the crate. Until this repo has a release
tag, by path, from a checkout next to it:

```toml
nimbra-core = { path = "../core/crates/nimbra-core" }
# once tagged:
nimbra-core = { git = "https://github.com/nimbra-mail/core", tag = "v0.1.0" }
```

The app brings the modules in by name (`use nimbra_core::{mail, gmail, …}`), so its code reads `crate::mail` as
before. The `test-support` feature gives the app's own tests temporary stores. The Mac app keeps its folders where
they have always been (`~/Library/Application Support/Nimbra`).

**iOS** ([ios](https://github.com/nimbra-mail/ios)) depends on the Swift package: by local path (`../core`) while
developing, or by this repo's URL once a release carries the XCFramework. In Swift:

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

A release carries the XCFramework, so that iOS can depend on the package by URL and checksum without building Rust:

1. `./scripts/build-ios-core.sh --release-zip` makes `NimbraFFI.xcframework.zip` and prints its checksum.
2. In `Package.swift`, set `releaseURL` to
   `https://github.com/nimbra-mail/core/releases/download/vX.Y.Z/NimbraFFI.xcframework.zip` and `releaseChecksum`
   to the checksum; commit, then tag `vX.Y.Z`.
3. Publish the GitHub release for the tag with the zip attached.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has how to work on it and the commit style
([Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)). Found a security problem? Report it
privately: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
