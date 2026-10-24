#!/usr/bin/env sh
# Finds a QEMU x86-64 emulator: $QEMU, then the system one, then the private
# copy installed by scripts/fetch-qemu.sh into $BV_TOOLS/qemu.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCAL="${BV_TOOLS:-$HOME/.cache/blackveil-os}/qemu"

if [ -n "$QEMU" ]; then
  exec "$QEMU" "$@"
elif command -v qemu-system-x86_64 >/dev/null 2>&1; then
  exec qemu-system-x86_64 "$@"
elif [ -x "$LOCAL/usr/bin/qemu-system-x86_64" ]; then
  LD_LIBRARY_PATH="$LOCAL/usr/lib/x86_64-linux-gnu:$LOCAL/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    exec "$LOCAL/usr/bin/qemu-system-x86_64" -L "$LOCAL/usr/share/seabios" -L "$LOCAL/usr/share/qemu" "$@"
else
  echo "qemu-system-x86_64 not found. Install it (sudo apt install qemu-system-x86) or run scripts/fetch-qemu.sh" >&2
  exit 127
fi
