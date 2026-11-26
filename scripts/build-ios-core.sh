#!/usr/bin/env bash
# Builds the mail engine for iOS: crates/nimbra-ffi as an XCFramework (device and Apple
# silicon simulator) plus its Swift bindings, into the Swift package at this repo's root.
#
#   ./scripts/build-ios-core.sh                 # release build, for the iOS app to use
#   ./scripts/build-ios-core.sh --release-zip   # the same, plus the zip and checksum a
#                                               # GitHub release carries (see README)
#   NIMBRA_IOS_PROFILE=debug ./scripts/build-ios-core.sh
#
# Writes, at the repo root:
#   NimbraFFI.xcframework                 the static libraries and their C header (ignored by git)
#   Sources/NimbraCore/NimbraCore.swift   the generated Swift API (kept in git, to review)
#   NimbraFFI.xcframework.zip             with --release-zip only (ignored by git)
#
# Needs Xcode and rustup with the aarch64-apple-ios and aarch64-apple-ios-sim targets
# (`rustup target add aarch64-apple-ios aarch64-apple-ios-sim`). It builds with rustup's
# stable toolchain even when another Rust (Homebrew's) comes first on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

PACKAGE="$PWD"
ZIP=0
for arg in "$@"; do
  case "$arg" in
    --release-zip) ZIP=1 ;;
    *) echo "error: unknown option $arg" >&2; exit 1 ;;
  esac
done
PROFILE="${NIMBRA_IOS_PROFILE:-release}"
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
# The iOS app's deployment target (ios/project.yml).
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-26.0}"

[ -f "$PACKAGE/Package.swift" ] || { echo "error: no Swift package at $PACKAGE" >&2; exit 1; }

# The iOS engine is given its sign-in clients by the app at run time: nothing is built in.
unset NIMBRA_BUILTIN_GOOGLE_CLIENT_ID NIMBRA_BUILTIN_GOOGLE_CLIENT_SECRET NIMBRA_BUILTIN_MICROSOFT_CLIENT_ID

command -v rustup >/dev/null || { echo "error: rustup is needed (https://rustup.rs)" >&2; exit 1; }
# rustup's own cargo and rustc, named outright: cargo would otherwise run the first rustc
# on PATH, which has no iOS targets when it is Homebrew's.
CARGO_BIN="$(rustup which --toolchain stable cargo)"
export RUSTC="$(rustup which --toolchain stable rustc)"
cargo() { "$CARGO_BIN" "$@"; }
installed=$'\n'"$(rustup target list --toolchain stable --installed)"$'\n'
for target in "${TARGETS[@]}"; do
  [[ "$installed" == *$'\n'"$target"$'\n'* ]] || {
    echo "error: missing Rust target $target: rustup target add ${TARGETS[*]}" >&2
    exit 1
  }
done

# Its own target folder: the Mac app may be built with another toolchain.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/ios}"
flags=()
[ "$PROFILE" = "release" ] && flags+=(--release)
# Xcode strips the app when it links it; stripping here needs rustup's rust-objcopy, which
# not every toolchain install can run.
export CARGO_PROFILE_RELEASE_STRIP=false

for target in "${TARGETS[@]}"; do
  echo "Building nimbra-ffi for $target ($PROFILE)"
  cargo build -p nimbra-ffi --lib "${flags[@]}" --target "$target"
done

# The bindings come from the library's own metadata, read from a host build of it.
echo "Generating the Swift bindings"
cargo build -p nimbra-ffi --lib "${flags[@]}"
GENERATED="$CARGO_TARGET_DIR/swift"
rm -rf "$GENERATED"
cargo run -q -p nimbra-ffi --features bindgen --bin uniffi-bindgen -- \
  generate --library "$CARGO_TARGET_DIR/$PROFILE/libnimbra_ffi.dylib" \
  --language swift --out-dir "$GENERATED"

HEADERS="$CARGO_TARGET_DIR/swift-headers"
rm -rf "$HEADERS"
mkdir -p "$HEADERS"
cp "$GENERATED/NimbraFFI.h" "$HEADERS/"
cp "$GENERATED/NimbraFFI.modulemap" "$HEADERS/module.modulemap"

echo "Making NimbraFFI.xcframework"
rm -rf "$PACKAGE/NimbraFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios/$PROFILE/libnimbra_ffi.a" -headers "$HEADERS" \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/$PROFILE/libnimbra_ffi.a" -headers "$HEADERS" \
  -output "$PACKAGE/NimbraFFI.xcframework" >/dev/null

mkdir -p "$PACKAGE/Sources/NimbraCore"
cp "$GENERATED/NimbraCore.swift" "$PACKAGE/Sources/NimbraCore/NimbraCore.swift"
if [ "$ZIP" = "1" ]; then
  rm -f NimbraFFI.xcframework.zip
  # Stored paths start at NimbraFFI.xcframework/, as SwiftPM expects.
  ditto -c -k --sequesterRsrc --keepParent NimbraFFI.xcframework NimbraFFI.xcframework.zip
  echo "Release zip: $PACKAGE/NimbraFFI.xcframework.zip"
  echo "Checksum: $(swift package compute-checksum NimbraFFI.xcframework.zip)"
fi
echo "Done: $PACKAGE"
