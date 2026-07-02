# guacd runtime

这里放置按平台构建好的 Apache Guacamole `guacd` 运行时。

期望路径：

- `runtime/guacd/linux/guacd`
- `runtime/guacd/windows/guacd.exe`

服务端也支持外部 `guacd`：

```bash
SERVERMANAGER_GUACD_HOST=127.0.0.1 SERVERMANAGER_GUACD_PORT=4822 ./servermanager
```

构建建议：

- Linux: 使用 Apache Guacamole server + FreeRDP 构建 `guacd`。
- Windows: 使用 MSYS2/MinGW + FreeRDP 构建 `guacd.exe`，并将必需 DLL 放在同目录。