#!/usr/bin/env sh
# Installs QEMU into $BV_TOOLS/qemu (default ~/.cache/blackveil-os) WITHOUT root, on Debian/Ubuntu hosts, by
# downloading the distribution's own packages and unpacking them locally.
# If you have sudo, `sudo apt install qemu-system-x86` is simpler.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# Kept outside the source tree: the ~140 MB download pushed the project past
# Bolt's 100 MB limit and caused saves to fail.
TOOLS="${BV_TOOLS:-$HOME/.cache/blackveil-os}"
WORK="$TOOLS/apt"
DEST="$TOOLS/qemu"
mkdir -p "$WORK/state/lists/partial" "$WORK/cache/archives/partial" "$DEST"

APT="-o Dir::State=$WORK/state -o Dir::State::status=/var/lib/dpkg/status -o Dir::Cache=$WORK/cache -o Debug::NoLocking=1 -o APT::Sandbox::User=$(id -un)"
apt-get $APT update
apt-get $APT install -y --download-only --no-install-recommends qemu-system-x86
for deb in "$WORK"/cache/archives/*.deb; do
  dpkg-deb -x "$deb" "$DEST"
done
# Run through sh: the execute bit on qemu.sh is not preserved by every copy of the project.
sh "$ROOT/scripts/qemu.sh" --version | head -1
