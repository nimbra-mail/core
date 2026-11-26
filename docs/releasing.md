# Releasing nimbra-core

A release is one command on the maintainer's Mac:

```sh
./scripts/release 0.2.0
```

It checks the engine, builds `NimbraFFI.xcframework.zip`, points `Package.swift` at it, tags `v0.2.0` and publishes
the GitHub Release with the zip and the changelog as its notes. Nothing is released by pushing to `main`.

You need Xcode 26, rustup's stable toolchain with the iOS targets (`rustup target add aarch64-apple-ios
aarch64-apple-ios-sim`) and the GitHub CLI, signed in (`gh auth login`).

## The changelog

Add a line under `## [Unreleased]` in [CHANGELOG.md](../CHANGELOG.md) with each change, in the same pull request. Its
readers use the crate and the Swift package, so say what changed in the engine or the Swift API, under `### Added`,
`### Changed` or `### Fixed`. Anything that breaks the crate's API or the Swift API (a renamed `Engine` method, a
changed record, a new required argument) goes under `### Breaking`, first, with what to change. Leave out refactors,
CI and docs.

The release turns Unreleased into `## [<version>] - <date>`, with a fresh empty Unreleased above it, and uses that
section as the release notes. With nothing under Unreleased, it drafts the section from the commits since the last tag
(`feat` under Added, `fix` and `perf` under Fixed, a `!` or `BREAKING CHANGE:` under Breaking) and waits for you to
review it (in `$EDITOR` when set). It never releases without notes.

## What the command does

It stops at the first problem, and nothing is committed or pushed until the zip is built and `Package.swift` points at
it (a stop puts the versions and `Package.swift` back).

1. **Checks** that you're on `main`, clean (except `CHANGELOG.md`) and in sync with GitHub, the version is
   `X.Y.Z` and newer than the last tag, the tag is free, `gh` is signed in, and rustup's stable toolchain has the iOS
   targets, `rustfmt` and `clippy`.
2. **Changelog**, as above.
3. **Version:** sets `version` in `crates/nimbra-core/Cargo.toml` and `crates/nimbra-ffi/Cargo.toml` and refreshes
   `Cargo.lock`, before anything is built, so `core_version()` in the released engine says the tag's version.
4. **Format, lint and test:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`.
5. **XCFramework:** `./scripts/build-ios-core.sh --release-zip`, and its checksum. It stops if the regenerated
   `Sources/NimbraCore/NimbraCore.swift` differs from the committed one: bindings are committed with the change that
   needed them.
6. **Package.swift:** sets `releaseURL` to
   `https://github.com/nimbra-mail/core/releases/download/v<version>/NimbraFFI.xcframework.zip` and
   `releaseChecksum` to the checksum.
7. **Commit and tag:** commits `chore(release): v<version>` (`CHANGELOG.md`, `Package.swift`, both crates'
   `Cargo.toml` and `Cargo.lock`), tags `v<version>`, and pushes both.
8. **GitHub Release:** publishes `v<version>` with the zip and the changelog section, then downloads the zip back and
   checks it against `Package.swift`. It prints the release's address and the lines for the apps.

`./scripts/release 0.2.0 --dry-run` does steps 1 to 6 and stops: nothing is committed, tagged, pushed or published,
and the versions and `Package.swift` are put back. `CHANGELOG.md` keeps the new section, so a real run uses it as it is.

## How the apps pick up a version

**macOS** (`desktop/Cargo.toml`, both the dependency and the dev-dependency with `test-support`):

```toml
nimbra-core = { git = "https://github.com/nimbra-mail/core", tag = "v0.2.0" }
```

**iOS** (`ios/project.yml`, then `xcodegen`): SwiftPM takes the XCFramework from the release by URL and checksum,
with no Rust build.

```yaml
packages:
  NimbraCore:
    url: https://github.com/nimbra-mail/core
    exactVersion: 0.2.0
```

To try an engine change in an app before it is released, run `scripts/local-core.sh on` in that app (it builds
against this checkout at `../core`), and `scripts/local-core.sh off` before committing there.

## Versions

While on 0.x: a patch (0.2.0 to 0.2.1) for fixes only, a minor (0.2.1 to 0.3.0) for anything new or anything
**Breaking**. After 1.0.0, a breaking change is a major version.

## When something goes wrong

- **It stopped after the tag was pushed** (the GitHub Release failed). Publish it by hand:
  `gh release create v<version> NimbraFFI.xcframework.zip --repo nimbra-mail/core --title v<version> --notes-file <the section>`.
- **A release went out broken.** Don't delete or move its tag: SwiftPM and Cargo cache what a tag pointed at. Fix it
  and release the next patch version.
