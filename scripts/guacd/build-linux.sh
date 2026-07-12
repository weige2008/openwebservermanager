#!/usr/bin/env bash
set -euo pipefail

GUACAMOLE_VERSION="${GUACAMOLE_VERSION:-1.5.5}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/runtime/guacd/linux}"
WORK_DIR="${GUACD_WORK_DIR:-${RUNNER_TEMP:-/tmp}/openwebservermanager-guacd-linux}"
SOURCE_DIR="$WORK_DIR/guacamole-server-$GUACAMOLE_VERSION"
ARCHIVE="$WORK_DIR/guacamole-server-$GUACAMOLE_VERSION.tar.gz"
INSTALL_ROOT="$WORK_DIR/stage"
PATCH_FILE="$SCRIPT_DIR/guacamole-server-1.5.5-cygwin.patch"

mkdir -p "$WORK_DIR"
if [[ ! -f "$ARCHIVE" ]]; then
  curl -fsSL "https://archive.apache.org/dist/guacamole/$GUACAMOLE_VERSION/source/guacamole-server-$GUACAMOLE_VERSION.tar.gz" -o "$ARCHIVE"
fi
rm -rf "$SOURCE_DIR" "$INSTALL_ROOT" "$OUTPUT_DIR"
tar -xzf "$ARCHIVE" -C "$WORK_DIR"
git -C "$SOURCE_DIR" apply --whitespace=error-all "$PATCH_FILE"

cd "$SOURCE_DIR"
autoreconf -fi
./configure \
  --prefix=/usr \
  --libdir=/usr/lib \
  --with-freerdp-plugin-dir=/usr/lib/freerdp2 \
  --disable-guacenc \
  --disable-guaclog \
  --disable-kubernetes \
  --disable-ssh-agent \
  --enable-allow-freerdp-snapshots
make -j"$(nproc)"
make DESTDIR="$INSTALL_ROOT" install

mkdir -p "$OUTPUT_DIR/bin" "$OUTPUT_DIR/lib" "$OUTPUT_DIR/usr/lib/freerdp2" "$OUTPUT_DIR/home"
cp "$INSTALL_ROOT/usr/sbin/guacd" "$OUTPUT_DIR/bin/guacd"
cp -a "$INSTALL_ROOT/usr/lib/"libguac*.so* "$OUTPUT_DIR/lib/"
if compgen -G "$INSTALL_ROOT/usr/lib/freerdp2/*.so*" >/dev/null; then
  cp -a "$INSTALL_ROOT/usr/lib/freerdp2/"*.so* "$OUTPUT_DIR/usr/lib/freerdp2/"
fi

declare -A dependencies=()
queue=("$OUTPUT_DIR/bin/guacd" "$OUTPUT_DIR/lib/"*.so*)
if compgen -G "$OUTPUT_DIR/usr/lib/freerdp2/*.so*" >/dev/null; then
  queue+=("$OUTPUT_DIR/usr/lib/freerdp2/"*.so*)
fi
for target in "${queue[@]}"; do
  while IFS= read -r dependency; do
    [[ -f "$dependency" ]] || continue
    case "$(basename "$dependency")" in
      ld-linux*.so*|libc.so*|libdl.so*|libm.so*|libpthread.so*|librt.so*) continue ;;
    esac
    dependencies["$dependency"]=1
  done < <(ldd "$target" 2>/dev/null | awk '/=> \/|^\// { for (i=1; i<=NF; i++) if ($i ~ /^\//) { print $i; break } }')
done
for dependency in "${!dependencies[@]}"; do
  cp -L "$dependency" "$OUTPUT_DIR/lib/$(basename "$dependency")"
done

chmod 0755 "$OUTPUT_DIR/bin/guacd"
cp "$SOURCE_DIR/LICENSE" "$OUTPUT_DIR/LICENSE.apache-guacamole.txt"
cp "$SOURCE_DIR/NOTICE" "$OUTPUT_DIR/NOTICE.apache-guacamole.txt"
manifest="$OUTPUT_DIR/manifest.json"
file_count=0
size_bytes=0
for _ in 1 2 3; do
cat > "$manifest" <<EOF
{
  "runtime": "guacd",
  "version": "$GUACAMOLE_VERSION",
  "platform": "linux-amd64",
  "toolchain": "gnu",
  "protocols": ["rdp", "vnc"],
  "executable": "bin/guacd",
  "files": $file_count,
  "size_bytes": $size_bytes
}
EOF
  file_count="$(find "$OUTPUT_DIR" -type f | wc -l | tr -d ' ')"
  size_bytes="$(du -sb "$OUTPUT_DIR" | awk '{print $1}')"
done
cat > "$manifest" <<EOF
{
  "runtime": "guacd",
  "version": "$GUACAMOLE_VERSION",
  "platform": "linux-amd64",
  "toolchain": "gnu",
  "protocols": ["rdp", "vnc"],
  "executable": "bin/guacd",
  "files": $file_count,
  "size_bytes": $size_bytes
}
EOF

echo "Built portable Linux guacd runtime at $OUTPUT_DIR"
echo "Files: $file_count, size: $((size_bytes / 1024 / 1024)) MB"
