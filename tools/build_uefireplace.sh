#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DEST=${1:-"$ROOT/tools/bin/UEFIReplace"}

for tool in git make g++ qmake-qt5; do
  command -v "$tool" >/dev/null || {
    echo "error: missing $tool" >&2
    echo "Fedora: sudo dnf install -y git gcc-c++ make qt5-qtbase-devel" >&2
    exit 1
  }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# UEFITool 0.28.0; verify the immutable commit as well as the tag name.
expected_commit=d9642c53e7b873fcce858ec2bea577f099b966d5
git -c advice.detachedHead=false clone --quiet --depth 1 --branch 0.28.0 \
  https://github.com/LongSoft/UEFITool.git "$tmp/UEFITool"
actual_commit=$(git -C "$tmp/UEFITool" rev-parse HEAD)
if [[ "$actual_commit" != "$expected_commit" ]]; then
  echo "error: UEFIReplace source commit mismatch: $actual_commit" >&2
  exit 1
fi
mkdir "$tmp/build"
cd "$tmp/build"
qmake-qt5 "$tmp/UEFITool/UEFIReplace/uefireplace.pro"
make -j"$(nproc)"

mkdir -p "$(dirname -- "$DEST")"
install -m 0755 UEFIReplace "$DEST"
echo "built $DEST"
sha256sum "$DEST"
