#!/usr/bin/env bash
set -euo pipefail

GUACAMOLE_VERSION="${OPENWEBSERVERMANAGER_GUACENC_VERSION:-1.3.0}"
GUACAMOLE_SHA256="${OPENWEBSERVERMANAGER_GUACENC_SHA256:-bc5511c7170841f90d437b5a07b7ec2f5bfd061f2a5bfc4e4d0fc4d7b303fb4c}"
INSTALL_PATH="${OPENWEBSERVERMANAGER_GUACENC_INSTALL_PATH:-/usr/local/bin/guacenc}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "guacenc installer only supports Linux" >&2
  exit 1
fi

if [[ -x "$INSTALL_PATH" ]] && command -v ffmpeg >/dev/null 2>&1 && "$INSTALL_PATH" 2>&1 | grep -q "version $GUACAMOLE_VERSION"; then
  echo "guacenc $GUACAMOLE_VERSION already installed at $INSTALL_PATH"
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "automatic guacenc installation currently requires apt-get" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  build-essential pkg-config curl ca-certificates \
  libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin \
  libossp-uuid-dev libguac-dev \
  libavcodec-dev libavformat-dev libavutil-dev libswscale-dev ffmpeg

workdir="$(mktemp -d /tmp/openwebservermanager-guacenc.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT
archive="$workdir/guacamole-server-$GUACAMOLE_VERSION.tar.gz"
source_dir="$workdir/guacamole-server-$GUACAMOLE_VERSION"
url="https://archive.apache.org/dist/guacamole/$GUACAMOLE_VERSION/source/guacamole-server-$GUACAMOLE_VERSION.tar.gz"

curl -fsSL "$url" -o "$archive"
echo "$GUACAMOLE_SHA256  $archive" | sha256sum -c -
tar -xzf "$archive" -C "$workdir"

cd "$source_dir"
./configure --disable-guacd --disable-guaclog --disable-ssh-agent --disable-kubernetes
# Guacamole 1.3.0 predates FFmpeg 6 and treats its deprecation warning as fatal.
sed -i -e 's/-Werror/-Wno-error=deprecated-declarations/' src/guacenc/Makefile
make -C src/libguac -j"$(nproc)"
make -C src/guacenc -j"$(nproc)"
install -m 0755 src/guacenc/.libs/guacenc "$INSTALL_PATH"

if ! "$INSTALL_PATH" 2>&1 | grep -q "version $GUACAMOLE_VERSION"; then
  echo "installed guacenc failed its version check" >&2
  exit 1
fi

apt-get clean
echo "installed guacenc $GUACAMOLE_VERSION at $INSTALL_PATH"
