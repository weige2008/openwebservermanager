# guacd runtime

Linux amd64 and Windows amd64 release packages include tested Apache Guacamole `guacd` runtimes with RDP and VNC plugins. Place custom runtime builds here when producing packages for other architectures.

Expected paths:

- `runtime/guacd/linux/bin/guacd`
- `runtime/guacd/windows/bin/guacd.exe`

You can also use an externally managed local `guacd`:

```bash
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1 OPENWEBSERVERMANAGER_GUACD_PORT=4822 ./openwebservermanager
```

Build notes:

- Linux: `bash scripts/guacd/build-linux.sh runtime/guacd/linux`
- Windows: `scripts/guacd/build-windows-cygwin.ps1 -OutputDir runtime/guacd/windows`

The Windows runtime uses the Cygwin POSIX compatibility layer because upstream guacd relies on process, descriptor, and pthread semantics that MinGW does not provide. All required Cygwin, FreeRDP, and VNC DLLs are copied into the portable runtime; users do not install Cygwin separately.

Validate custom builds with `scripts/guacd/test-linux-runtime.sh` or `scripts/guacd/test-windows-runtime.ps1` before packaging.

Recording and drive transfer directories are created by openwebservermanager. The default mode is `0770`; set `OPENWEBSERVERMANAGER_SHARED_DIR_MODE` only when your guacd deployment requires a different sharing model.
