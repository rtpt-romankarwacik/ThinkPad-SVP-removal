#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DEST=${1:-"$ROOT/tools/bin/UEFIExtract"}
VERSION=A75
EXPECTED_SHA256=5ee05d0da0c235626de67959d6cd97767e0d7ac67d42c8839e5972e8c23fd5a5
URL="https://github.com/LongSoft/UEFITool/releases/download/$VERSION/UEFIExtract_NE_${VERSION}_x64_linux.zip"

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "error: the pinned prebuilt verifier is only for Linux x86_64" >&2
  exit 1
fi
for tool in curl unzip sha256sum; do
  command -v "$tool" >/dev/null || { echo "error: missing $tool" >&2; exit 1; }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --fail --location --silent --show-error "$URL" -o "$tmp/UEFIExtract.zip"
echo "$EXPECTED_SHA256  $tmp/UEFIExtract.zip" | sha256sum --check --status || {
  echo "error: UEFIExtract archive checksum mismatch" >&2
  exit 1
}
unzip -q "$tmp/UEFIExtract.zip" -d "$tmp/unpacked"
binary=$(find "$tmp/unpacked" -maxdepth 1 -type f -iname 'uefiextract*' -print -quit)
[[ -n $binary ]] || { echo "error: archive contains no UEFIExtract binary" >&2; exit 1; }
mkdir -p "$(dirname -- "$DEST")"
install -m 0755 "$binary" "$DEST"
echo "installed $DEST (UEFIExtract NE $VERSION)"
