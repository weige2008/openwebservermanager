const state = {
  view: "dashboard",
  servers: [],
  credentials: [],
  sessions: [],
  audit_logs: [],
  modal: null,
  toast: "",
  workspace: null,
};

const app = document.querySelector("#app");
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

function html(strings, ...values) {
  return strings.reduce((acc, item, i) => acc + item + (values[i] ?? ""), "");
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToText(value) {
  const binary = atob(value || "");
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return textDecoder.decode(bytes, { stream: true });
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function refresh() {
  const data = await api("/api/bootstrap");
  Object.assign(state, data);
  render();
}

function toast(message) {
  state.toast = message;
  render();
  setTimeout(() => {
    state.toast = "";
    render();
  }, 4200);
}

function render() {
  if (state.workspace) {
    renderWorkspace();
    return;
  }
  app.innerHTML = html`
    <div class="app-shell">
      <aside class="sidebar">
        <div class="brand"><span class="brand-mark"></span><span>ServerManager</span></div>
        <nav class="nav">
          ${navButton("dashboard", "仪表盘")}
          ${navButton("servers", "服务器")}
          ${navButton("credentials", "凭据")}
          ${navButton("sessions", "会话")}
          ${navButton("audit", "审计")}
        </nav>
      </aside>
      <main class="main">
        <header class="topbar">
          <h1>${title()}</h1>
          <div class="actions">
            <button onclick="refresh()">刷新</button>
            <button class="primary" onclick="openModal('server')">添加服务器</button>
            <button onclick="openModal('credential')">添加凭据</button>
          </div>
        </header>
        <section class="content">${view()}</section>
      </main>
    </div>
    ${state.modal ? modal() : ""}
    ${state.toast ? `<div class="toast">${escapeHTML(state.toast)}</div>` : ""}
  `;
}

function navButton(view, label) {
  return `<button class="${state.view === view ? "active" : ""}" onclick="setView('${view}')">${label}</button>`;
}

function setView(view) {
  state.view = view;
  render();
}

function title() {
  return { dashboard: "仪表盘", servers: "服务器", credentials: "凭据", sessions: "连接会话", audit: "审计日志" }[state.view];
}

function view() {
  if (state.view === "servers") return serversView();
  if (state.view === "credentials") return credentialsView();
  if (state.view === "sessions") return sessionsView();
  if (state.view === "audit") return auditView();
  return dashboardView();
}

function dashboardView() {
  const active = state.sessions.filter((s) => s.status === "active").length;
  return html`
    <div class="grid cols-3">
      ${stat("服务器", state.servers.length)}
      ${stat("凭据", state.credentials.length)}
      ${stat("活跃会话", active)}
    </div>
    <div style="height:16px"></div>
    <div class="panel"><div class="panel-header"><h2 class="panel-title">最近会话</h2></div>${sessionsTable(state.sessions.slice(-8).reverse())}</div>
  `;
}

function stat(label, value) {
  return `<div class="panel panel-body stat"><span class="label">${label}</span><span class="value">${value}</span></div>`;
}

function serversView() {
  return html`
    <div class="panel">
      <div class="panel-header"><h2 class="panel-title">服务器资产</h2><button class="primary" onclick="openModal('server')">添加服务器</button></div>
      <table>
        <thead><tr><th>名称</th><th>地址</th><th>系统</th><th>端口</th><th></th></tr></thead>
        <tbody>
          ${state.servers.map((s) => html`
            <tr>
              <td>${escapeHTML(s.name)}<div class="muted">${escapeHTML(s.description || "")}</div></td>
              <td>${escapeHTML(s.host)}</td>
              <td><span class="badge">${escapeHTML(s.os)}</span></td>
              <td>SSH ${s.ssh_port || 22} / RDP ${s.rdp_port || 3389}</td>
              <td class="actions"><button class="primary" onclick="startSSH('${s.id}')">SSH</button><button onclick="startRDP('${s.id}')">RDP</button></td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>`;
}

function credentialsView() {
  return html`
    <div class="panel">
      <div class="panel-header"><h2 class="panel-title">凭据库</h2><button class="primary" onclick="openModal('credential')">添加凭据</button></div>
      <table>
        <thead><tr><th>名称</th><th>类型</th><th>用户</th><th>域</th></tr></thead>
        <tbody>
          ${state.credentials.map((c) => html`
            <tr><td>${escapeHTML(c.name)}</td><td><span class="badge">${escapeHTML(c.type)}</span></td><td>${escapeHTML(c.username)}</td><td>${escapeHTML(c.domain || "-")}</td></tr>`).join("")}
        </tbody>
      </table>
    </div>`;
}

function sessionsView() {
  return `<div class="panel"><div class="panel-header"><h2 class="panel-title">连接会话</h2></div>${sessionsTable(state.sessions.slice().reverse())}</div>`;
}

function sessionsTable(sessions) {
  return html`
    <table>
      <thead><tr><th>协议</th><th>服务器</th><th>状态</th><th>开始时间</th><th>录屏</th><th></th></tr></thead>
      <tbody>
        ${sessions.map((s) => {
          const server = state.servers.find((item) => item.id === s.server_id);
          return html`
            <tr>
              <td><span class="badge">${escapeHTML(s.protocol)}</span></td>
              <td>${escapeHTML(server?.name || s.server_id)}</td>
              <td>${statusBadge(s.status)}</td>
              <td>${new Date(s.started_at).toLocaleString()}</td>
              <td>${s.recording_path ? escapeHTML(s.recording_size || 0) + " bytes" : "-"}</td>
              <td class="actions">${s.recording_path ? `<button onclick="downloadRecording('${s.id}')">下载录屏</button>` : ""}<button onclick="closeSession('${s.id}')">关闭</button></td>
            </tr>`;
        }).join("")}
      </tbody>
    </table>`;
}

function statusBadge(status) {
  const cls = status === "active" ? "green" : status === "failed" ? "red" : status === "pending" ? "yellow" : "";
  return `<span class="badge ${cls}">${escapeHTML(status)}</span>`;
}

function auditView() {
  return html`
    <div class="panel">
      <div class="panel-header"><h2 class="panel-title">审计日志</h2></div>
      <table>
        <thead><tr><th>时间</th><th>动作</th><th>目标</th><th>来源</th><th>详情</th></tr></thead>
        <tbody>
          ${state.audit_logs.slice().reverse().map((a) => html`
            <tr><td>${new Date(a.created_at).toLocaleString()}</td><td>${escapeHTML(a.action)}</td><td>${escapeHTML(a.target_id)}</td><td>${escapeHTML(a.client_ip)}</td><td>${escapeHTML(a.detail || "")}</td></tr>`).join("")}
        </tbody>
      </table>
    </div>`;
}

function openModal(type) { state.modal = type; render(); }
function closeModal() { state.modal = null; render(); }
function modal() { return state.modal === "credential" ? credentialModal() : serverModal(); }

function serverModal() {
  return html`
    <div class="modal-backdrop"><div class="modal">
      <div class="panel-header"><h2 class="panel-title">添加服务器</h2><button onclick="closeModal()">关闭</button></div>
      <form class="panel-body form-grid" onsubmit="createServer(event)">
        ${field("name", "名称")}${field("host", "主机地址")}
        <div class="field"><label>系统</label><select name="os"><option value="linux">Linux</option><option value="windows">Windows</option></select></div>
        ${field("group", "分组")}${field("ssh_port", "SSH 端口", "22")}${field("rdp_port", "RDP 端口", "3389")}
        <div class="field full"><label>描述</label><textarea name="description"></textarea></div>
        <div class="actions full"><button type="button" onclick="closeModal()">取消</button><button class="primary">保存</button></div>
      </form>
    </div></div>`;
}

function credentialModal() {
  return html`
    <div class="modal-backdrop"><div class="modal">
      <div class="panel-header"><h2 class="panel-title">添加凭据</h2><button onclick="closeModal()">关闭</button></div>
      <form class="panel-body form-grid" onsubmit="createCredential(event)">
        ${field("name", "名称")}
        <div class="field"><label>类型</label><select name="type"><option value="ssh_password">SSH 密码</option><option value="ssh_key">SSH 私钥</option><option value="rdp_password">RDP 密码</option></select></div>
        ${field("username", "用户名")}${field("domain", "域 / 工作组")}${field("password", "密码", "", "password")}
        <div class="field full"><label>私钥</label><textarea name="private_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></div>
        ${field("passphrase", "私钥 passphrase", "", "password")}
        <div class="actions full"><button type="button" onclick="closeModal()">取消</button><button class="primary">保存</button></div>
      </form>
    </div></div>`;
}

function field(name, label, value = "", type = "text") {
  return `<div class="field"><label>${label}</label><input name="${name}" type="${type}" value="${escapeHTML(value)}" /></div>`;
}

async function createServer(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.ssh_port = Number(data.ssh_port || 22);
  data.rdp_port = Number(data.rdp_port || 3389);
  try { await api("/api/servers", { method: "POST", body: JSON.stringify(data) }); state.modal = null; await refresh(); toast("服务器已添加"); } catch (err) { toast(err.message); }
}

async function createCredential(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  try { await api("/api/credentials", { method: "POST", body: JSON.stringify(data) }); state.modal = null; await refresh(); toast("凭据已添加"); } catch (err) { toast(err.message); }
}

function compatibleCredentials(protocol) {
  return state.credentials.filter((c) => protocol === "ssh" ? c.type === "ssh_password" || c.type === "ssh_key" : c.type === "rdp_password");
}

async function chooseCredential(protocol) {
  const items = compatibleCredentials(protocol);
  if (!items.length) { toast(`没有可用的 ${protocol.toUpperCase()} 凭据`); return null; }
  if (items.length === 1) return items[0].id;
  const label = items.map((item, index) => `${index + 1}. ${item.name} (${item.username})`).join("\n");
  const pick = prompt(`选择凭据：\n${label}`, "1");
  const idx = Number(pick) - 1;
  return items[idx]?.id || null;
}

async function startSSH(serverID) {
  const credentialID = await chooseCredential("ssh");
  if (!credentialID) return;
  try {
    const session = await api("/api/connections/ssh", { method: "POST", body: JSON.stringify({ server_id: serverID, credential_id: credentialID, cols: 120, rows: 32, term: "xterm-256color" }) });
    state.workspace = { type: "ssh", session };
    render();
    connectSSH(session);
  } catch (err) { toast(err.message); }
}

async function startRDP(serverID) {
  const credentialID = await chooseCredential("rdp");
  if (!credentialID) return;
  try {
    const width = window.innerWidth;
    const height = window.innerHeight - 54;
    const session = await api("/api/connections/rdp", { method: "POST", body: JSON.stringify({ server_id: serverID, credential_id: credentialID, width, height, dpi: 96 }) });
    state.workspace = { type: "rdp", session };
    render();
    connectRDP(session);
  } catch (err) { toast(err.message); }
}

function renderWorkspace() {
  const session = state.workspace.session;
  app.innerHTML = html`
    <div class="workspace">
      <div class="workspace-toolbar">
        <div><strong>${session.protocol.toUpperCase()}</strong> <span class="muted">${session.id}</span></div>
        <div class="actions">
          ${session.protocol === "rdp" ? '<button onclick="sendClipboard()">剪贴板</button><button onclick="uploadRDPFile()">上传文件</button>' : ""}
          <button onclick="leaveWorkspace()">返回</button><button class="danger" onclick="closeWorkspace()">断开</button>
        </div>
      </div>
      ${session.protocol === "ssh" ? '<div id="terminal" class="terminal" tabindex="0"></div>' : '<div id="rdp" class="rdp-stage"></div>'}
    </div>
    ${state.toast ? `<div class="toast">${escapeHTML(state.toast)}</div>` : ""}`;
}

function connectSSH(session) {
  const terminalEl = document.querySelector("#terminal");
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${proto}://${location.host}/api/connections/ssh/${session.id}/ws?cols=120&rows=32&term=xterm-256color`);
  state.workspace.socket = socket;

  const sendInput = (data) => {
    if (data && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "stdin", data: bytesToBase64(textEncoder.encode(data)) }));
    }
  };

  let writeOutput;
  if (window.Terminal) {
    const term = new Terminal({ cursorBlink: true, convertEol: true, fontFamily: 'Cascadia Mono, JetBrains Mono, Consolas, monospace', fontSize: 13, theme: { background: '#030305', foreground: '#d4d4d8' } });
    const fit = window.FitAddon ? new FitAddon.FitAddon() : null;
    if (fit) term.loadAddon(fit);
    term.open(terminalEl);
    if (fit) fit.fit();
    term.focus();
    term.write("Connecting...\r\n");
    term.onData(sendInput);
    writeOutput = (text) => term.write(text.replaceAll("\n", "\r\n"));
    window.onresize = () => {
      if (fit) fit.fit();
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
    };
  } else {
    terminalEl.textContent = "Connecting...\n";
    terminalEl.focus();
    writeOutput = (text) => {
      terminalEl.textContent += text;
      terminalEl.scrollTop = terminalEl.scrollHeight;
    };
    terminalEl.onkeydown = (event) => {
      event.preventDefault();
      let data = "";
      if (event.ctrlKey && event.key.length === 1) data = String.fromCharCode(event.key.toUpperCase().charCodeAt(0) - 64);
      else if (event.key === "Enter") data = "\r";
      else if (event.key === "Backspace") data = "\x7f";
      else if (event.key === "Tab") data = "\t";
      else if (event.key === "ArrowUp") data = "\x1b[A";
      else if (event.key === "ArrowDown") data = "\x1b[B";
      else if (event.key === "ArrowRight") data = "\x1b[C";
      else if (event.key === "ArrowLeft") data = "\x1b[D";
      else if (event.key.length === 1) data = event.key;
      sendInput(data);
    };
    terminalEl.onpaste = (event) => {
      event.preventDefault();
      sendInput(event.clipboardData?.getData("text") || "");
    };
    window.onresize = () => {
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "resize", cols: 120, rows: 32 }));
    };
  }

  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === "ready") writeOutput("Connected.\n");
    if (msg.type === "stdout" || msg.type === "stderr") writeOutput(base64ToText(msg.data));
    if (msg.type === "error") writeOutput(`\n[error] ${msg.data}\n`);
  };
  socket.onclose = () => writeOutput("\n[disconnected]\n");
}
function connectRDP(session) {
  const container = document.querySelector("#rdp");
  if (!window.Guacamole) {
    container.innerHTML = '<div class="panel panel-body" style="margin:20px">缺少 /vendor/guacamole-common.min.js。请放置 guacamole-common-js 后重新连接。</div>';
    return;
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const width = window.innerWidth;
  const height = window.innerHeight - 54;
  const tunnel = new Guacamole.WebSocketTunnel(`${proto}://${location.host}/api/connections/rdp/${session.id}/tunnel?width=${width}&height=${height}&dpi=96`);
  const client = new Guacamole.Client(tunnel);
  state.workspace.client = client;
  container.appendChild(client.getDisplay().getElement());
  client.connect("");
  const mouse = new Guacamole.Mouse(client.getDisplay().getElement());
  mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = (mouseState) => client.sendMouseState(mouseState);
  const keyboard = new Guacamole.Keyboard(document);
  keyboard.onkeydown = (keysym) => client.sendKeyEvent(1, keysym);
  keyboard.onkeyup = (keysym) => client.sendKeyEvent(0, keysym);
  client.onerror = (err) => toast(err.message || "RDP 连接失败");
  window.onunload = () => client.disconnect();
}

function sendClipboard() {
  const text = prompt("发送到远程剪贴板");
  const client = state.workspace?.client;
  if (!client || text == null || !window.Guacamole) return;
  const stream = client.createClipboardStream("text/plain");
  const writer = new Guacamole.StringWriter(stream);
  writer.sendText(text);
  writer.sendEnd();
}

function uploadRDPFile() {
  const client = state.workspace?.client;
  if (!client || !window.Guacamole) return;
  const input = document.createElement("input");
  input.type = "file";
  input.onchange = () => {
    const file = input.files?.[0];
    if (!file) return;
    const stream = client.createFileStream(file.type || "application/octet-stream", file.name);
    const writer = new Guacamole.BlobWriter(stream);
    writer.oncomplete = () => toast("文件已发送");
    writer.sendBlob(file);
    writer.sendEnd();
  };
  input.click();
}

function downloadRecording(id) {
  location.href = `/api/connections/${id}/recording.zip`;
}
async function closeSession(id) {
  try { await api(`/api/connections/${id}/close`, { method: "POST", body: "{}" }); await refresh(); } catch (err) { toast(err.message); }
}

function leaveWorkspace() {
  state.workspace = null;
  window.onresize = null;
  refresh();
}

async function closeWorkspace() {
  const ws = state.workspace;
  if (ws?.socket) ws.socket.close();
  if (ws?.client) ws.client.disconnect();
  if (ws?.session) await closeSession(ws.session.id);
  state.workspace = null;
  window.onresize = null;
  await refresh();
}

refresh().catch((err) => { app.innerHTML = `<div class="toast">${escapeHTML(err.message)}</div>`; });