#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./build_ffs.sh /path/to/edk2

Builds ExploitReplica.inf and ExploitReplicaBO.inf inside an existing edk2
checkout and writes BootOption.ffs and LenovoTranslateService.ffs here.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && echo 0 || echo 2)
fi

EDK2=$(realpath "$1")
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
APP_DIR="$EDK2/MdeModulePkg/Application/ThinkPadSvpRemoval"
DSC="$EDK2/MdeModulePkg/MdeModulePkg.dsc"

if [[ ! -f "$EDK2/edksetup.sh" ]]; then
  echo "error: $EDK2 is not an edk2 checkout" >&2
  exit 1
fi

missing=()
for tool in make gcc g++ nasm iasl; do
  command -v "$tool" >/dev/null || missing+=("$tool")
done
if [[ ! -e /usr/include/uuid/uuid.h && ! -e /usr/local/include/uuid/uuid.h ]]; then
  missing+=("uuid/uuid.h")
fi
if (( ${#missing[@]} )); then
  echo "error: missing build prerequisite(s): ${missing[*]}" >&2
  echo "Fedora: sudo dnf install -y git gcc gcc-c++ make nasm acpica-tools python3 libuuid-devel" >&2
  echo "Debian/Ubuntu: sudo apt install build-essential uuid-dev iasl nasm python3 git" >&2
  exit 1
fi

mkdir -p "$APP_DIR"
cp "$REPO"/ExploitReplica.c "$REPO"/ExploitReplicaBO.c "$REPO"/ExploitReplica.inf "$REPO"/ExploitReplicaBO.inf "$APP_DIR"/

cd "$EDK2"
# Create Conf/ from templates if this is a fresh checkout. edksetup.sh expects
# unset variables, so temporarily disable nounset.
set +u
# shellcheck disable=SC1091
source edksetup.sh BaseTools >/dev/null
set -u
cd "$REPO"

# New edk2 uses TOOL_CHAIN_TAG=GCC; older checkouts used GCC5.
TOOL_CHAIN=GCC
if grep -q '^\*_GCC5_' "$EDK2/Conf/tools_def.txt"; then
  TOOL_CHAIN=GCC5
fi
BUILD_TARGET=RELEASE

for inf in \
  'MdeModulePkg/Application/ThinkPadSvpRemoval/ExploitReplica.inf' \
  'MdeModulePkg/Application/ThinkPadSvpRemoval/ExploitReplicaBO.inf'; do
  if ! grep -Fq "$inf" "$DSC"; then
    python3 - "$DSC" "$inf" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
inf = sys.argv[2]
s = p.read_text()
marker = '[Components]\n'
if marker not in s:
    raise SystemExit('MdeModulePkg.dsc has no [Components] section')
s = s.replace(marker, marker + '  ' + inf + '\n', 1)
p.write_text(s)
PY
  fi
done

cd "$EDK2"
# Build BaseTools C utilities on a fresh checkout. GenDepex is Python, while
# GenSec and GenFfs require the C tool build.
if [[ ! -x BaseTools/Source/C/bin/GenSec || ! -x BaseTools/Source/C/bin/GenFfs ]]; then
  make -C BaseTools
fi

BUILD_ARGS=(-a X64 -b "$BUILD_TARGET" -t "$TOOL_CHAIN" -p MdeModulePkg/MdeModulePkg.dsc)
build "${BUILD_ARGS[@]}" -m MdeModulePkg/Application/ThinkPadSvpRemoval/ExploitReplica.inf
build "${BUILD_ARGS[@]}" -m MdeModulePkg/Application/ThinkPadSvpRemoval/ExploitReplicaBO.inf

OUT="$EDK2/Build/MdeModule/${BUILD_TARGET}_${TOOL_CHAIN}/X64/MdeModulePkg/Application/ThinkPadSvpRemoval"
cp "$OUT/ExploitReplica/OUTPUT/LenovoTranslateService.efi" "$REPO/"
cp "$OUT/ExploitReplicaBO/OUTPUT/BootOption.efi" "$REPO/"

cd "$REPO"
./genWhole.sh BootOption E0746C42-D3F9-4F8B-B211-1410957B9FF5
./genWhole.sh LenovoTranslateService 826BCF56-BAC4-43F4-8EA1-8CDF0A121ABD

echo "Built: $REPO/BootOption.ffs $REPO/LenovoTranslateService.ffs"
