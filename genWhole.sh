#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <BaseName-without-.efi> <FFS-GUID>" >&2
  exit 2
fi

name="$1"
guid="$2"

for tool in GenSec GenFfs GenDepex; do
  command -v "$tool" >/dev/null || { echo "error: $tool not found; source edksetup.sh BaseTools first" >&2; exit 1; }
done
[[ -f "$name.efi" ]] || { echo "error: $name.efi not found" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

GenDepex -q -o "$tmp/depex.bin" -t UEFI_DRIVER -e TRUE
GenSec -q -o "$tmp/depex.sec" "$tmp/depex.bin" -S EFI_SECTION_DXE_DEPEX
GenSec -q -o "$tmp/pe32.sec" "$name.efi" -S EFI_SECTION_PE32
GenSec -q -o "$tmp/name.sec" -S EFI_SECTION_USER_INTERFACE -n "$name"
GenSec -q -o "$tmp/ver.sec" -S EFI_SECTION_VERSION -j 0 -n ".0"
GenFfs -q -g "$guid" -o "$name.ffs" \
  -i "$tmp/depex.sec" -i "$tmp/pe32.sec" -i "$tmp/name.sec" -i "$tmp/ver.sec" \
  -t EFI_FV_FILETYPE_DRIVER
