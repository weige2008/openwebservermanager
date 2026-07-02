# Vendor assets

RDP Web 客户端需要 Apache Guacamole 的 `guacamole-common-js` 浏览器库。SSH 终端优先使用 `xterm.js`，未放置时会退回内置轻量终端。

将构建后的文件放在：

```text
cmd/servermanager/static/vendor/guacamole-common.min.js
cmd/servermanager/static/vendor/xterm.js
cmd/servermanager/static/vendor/xterm-addon-fit.js
cmd/servermanager/static/vendor/xterm.css
```

当前仓库不直接复制第三方前端库源码；后续打包时可从 Apache Guacamole 发布包或 npm 包生成这些文件。