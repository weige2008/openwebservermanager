# guacd runtime

Place native Apache Guacamole `guacd` runtime builds in this directory when you want openwebservermanager to start a bundled gateway process.

Expected paths:

- `runtime/guacd/linux/guacd`
- `runtime/guacd/windows/guacd.exe`

You can also use an externally managed local `guacd`:

```bash
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1 OPENWEBSERVERMANAGER_GUACD_PORT=4822 ./openwebservermanager
```

Build notes:

- Linux: build Apache Guacamole server with FreeRDP support.
- Windows: build with MSYS2/MinGW and FreeRDP, then place required DLLs next to `guacd.exe`.

Recording and drive transfer directories are created by openwebservermanager. The default mode is `0770`; set `OPENWEBSERVERMANAGER_SHARED_DIR_MODE` only when your guacd deployment requires a different sharing model.
