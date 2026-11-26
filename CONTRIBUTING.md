# Contributing to nimbra-core

nimbra-core is the mail engine both Nimbra apps run. A change here reaches the macOS and the iOS app at once, so it
is held to the bar of both. Bug fixes are welcome; for anything bigger, open a discussion first and wait for a yes.

## Getting it running

You need a Mac with Xcode 26 or later and Rust through `rustup` (stable).

```sh
cargo test --workspace                 # every unit test, no network
./scripts/build-ios-core.sh            # the iOS XCFramework and the Swift API
```

To see a change in an app, check out [desktop](https://github.com/nimbra-mail/desktop) or
[ios](https://github.com/nimbra-mail/ios) next to this repo (`../desktop`, `../ios`): both build from `../core`.

## What a good change looks like

- **No UI.** Nothing here may need a window or a UI framework. What only one app needs stays in that app.
- **The macOS app behaves the same.** After a change, `cargo build`, `cargo test` and `cargo clippy --all-targets`
  in `../desktop` pass as before.
- **Tests run the real code**, against local fakes (an HTTP fake for the network layer, `Store::temp` for the
  store), never a real account, the real Keychain or the Mac app's folders. The IMAP and SMTP code also has live
  tests against local servers: run them when you change `imap_mail.rs`, `smtp.rs` or `mime.rs` (setup in
  [docs/testing.md](docs/testing.md)).
- **The Swift API stays coherent.** A new `Engine` method says in its doc whether it goes to the network. After a
  change to `crates/nimbra-ffi`, run `./scripts/build-ios-core.sh` and commit the regenerated
  `Sources/NimbraCore/NimbraCore.swift` (CI checks it is current).
- **Security first.** Secrets never in code, logs, errors or the repo. Untrusted mail is parsed with limits. TLS
  certificates are always checked.
- **A line in the changelog.** Add one under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) with each change
  to the engine or the Swift API, and mark anything that breaks either **Breaking**
  ([docs/releasing.md](docs/releasing.md)).
- **No em dashes** in comments, docs or messages.

## Commits and pull requests

Commits and pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
`feat(ffi): add counts for all inboxes`, `fix(imap): …`. The description starts lowercase and has no period. No AI
mentions and no co-author lines.

Found a security problem? Don't open an issue: see [SECURITY.md](SECURITY.md).
