#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -e

# Arguments:
#   $1: platform (linux|mac|windows)
#   $2: arch (optional, for mac: x86_64|aarch64)
#   $3: pgo_artifact_name (optional)

PLATFORM="$1"
ARCH="$2"
PGO_ARTIFACT_NAME="$3"

echo "Setting up Rust for platform=$PLATFORM, arch=$ARCH, pgo_artifact=$PGO_ARTIFACT_NAME"

# Install and use the Rust version aligned with Firefox 156
RUST_VERSION="1.95.0"
rustup toolchain install "$RUST_VERSION"
rustup default "$RUST_VERSION"

if [[ "$PLATFORM" == "windows" ]]; then
  rustup target add x86_64-pc-windows-msvc --toolchain "$RUST_VERSION"
elif [[ "$PLATFORM" == "linux" ]]; then
  if [[ "$ARCH" == "aarch64" ]]; then
    rustup target add aarch64-unknown-linux-gnu --toolchain "$RUST_VERSION"
  else
    rustup target add x86_64-unknown-linux-gnu --toolchain "$RUST_VERSION"
  fi
elif [[ "$PLATFORM" == "mac" ]]; then
  if [[ "$ARCH" == "x86_64" ]]; then
    TARGET="x86_64-apple-darwin"
  else
    TARGET="aarch64-apple-darwin"
  fi

  echo "Mac target: $TARGET"

  # Add target to the specific toolchain
  rustup target add "$TARGET" --toolchain "$RUST_VERSION"

  # Verify target is installed
  echo "Verifying Rust target installation for $RUST_VERSION:"
  rustup target list --toolchain "$RUST_VERSION" --installed | grep "$TARGET" || {
    echo "ERROR: Target $TARGET not found in $RUST_VERSION toolchain"
    echo "Attempting to add target again..."
    rustup target add "$TARGET" --toolchain "$RUST_VERSION"
  }
fi

echo "Rust configuration complete:"
rustc --version --verbose
echo "Installed targets:"
rustup target list --installed

export CARGO_INCREMENTAL=0
