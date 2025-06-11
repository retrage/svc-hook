#!/bin/sh
set -e

# This script prepares a simple FreeBSD rootfs for cross compilation
# using QEMU user mode. It downloads the base system and extracts it
# into ./freebsd-rootfs.

VERSION="13.2-RELEASE"
ARCH="aarch64"
ROOTFS_DIR="freebsd-rootfs"

if ! command -v qemu-aarch64-static >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y qemu-user-static
fi

mkdir -p "$ROOTFS_DIR"
BASE_URL="https://download.freebsd.org/ftp/releases/${ARCH}/${ARCH}/${VERSION}/base.txz"

echo "Fetching FreeBSD base from $BASE_URL"
curl -L "$BASE_URL" -o base.txz

echo "Extracting base system..."
bsdtar -C "$ROOTFS_DIR" -xf base.txz

echo "FreeBSD rootfs created at $ROOTFS_DIR"
