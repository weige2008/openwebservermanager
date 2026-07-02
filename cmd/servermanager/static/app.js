const state = {
  initialized: false,
  route: routeFromLocation(),
  auth: null,
  view: localStorage.getItem("servermanager:view") || "overview",
  theme: localStorage.getItem("servermanager:theme") || "light",
  servers: [],
  credentials: [],
  sessions: [],
  audit_logs: [],
  guacd: null,
  modal: null,
  toast: "",
  workspace: null,
};

const app = document.querySelector("#app");
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

applyTheme();

window.addEventListener("popstate", () => {
  state.route = routeFromLocation();
  render();
});

window.addEventListener(
  "scroll",
  () => document.body.classList.toggle("is-scrolled", window.scrollY > 18),
  { passive: true },
);

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

function routeFromLocation() {
  const path = location.pathname.replace(/\/+$/, "") || "/";
  if (path === "/login" || path === "/sign-in") return "login";
  if (path === "/app" || path === "/dashboard") return "app";
  return "home";
}

function navigate(path) {
  history.pushState({}, "", path);
  state.route = routeFromLocation();
  render();
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  const res = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  const data = await res.json().catch(() => ({}));

  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    clearPrivateState();
    state.auth = null;
    navigate("/login");
    throw new Error(data.error || "请先登录");
  }

  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function init() {
  try {
    const me = await api("/api/auth/me");
    state.auth = me.user;
    await refresh({ silent: true });
  } catch (_) {
    clearPrivateState();
  } finally {
    state.initialized = true;
    render();
  }
}

async function refresh(options = {}) {
  if (!state.auth) return;
  const data = await api("/api/bootstrap");
  state.servers = data.servers || [];
  state.credentials = data.credentials || [];
  state.sessions = data.sessions || [];
  state.audit_logs = data.audit_logs || [];
  state.guacd = data.guacd || null;
  if (!options.silent) toast("数据已刷新");
  render();
}

function clearPrivateState() {
  state.servers = [];
  state.credentials = [];
  state.sessions = [];
  state.audit_logs = [];
  state.guacd = null;
  state.workspace = null;
}

function toast(message) {
  state.toast = message;
  render();
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => {
    state.toast = "";
    render();
  }, 3600);
}

function applyTheme() {
  document.documentElement.classList.toggle("dark", state.theme === "dark");
}

function toggleTheme() {
  state.theme = state.theme === "dark" ? "light" : "dark";
  localStorage.setItem("servermanager:theme", state.theme);
  applyTheme();
  render();
}

function render() {
  if (!state.initialized) {
    app.innerHTML = `<div class="boot-screen">${brand("lg")}<div class="boot-card">正在加载控制台...</div></div>`;
    return;
  }

  if (state.workspace) {
    renderWorkspace();
    return;
  }

  if (!state.auth) {
    app.innerHTML =
      state.route === "login" || state.route === "app"
        ? signInPage()
        : landingPage(false);
    return;
  }

  if (state.route === "login") {
    navigate("/app");
    return;
  }

  app.innerHTML = state.route === "home" ? landingPage(true) : appShell();
}

function brand(size = "") {
  return html`<div class="brand ${size}">
    <span class="brand-mark" aria-hidden="true"></span>
    <span class="brand-name">ServerManager</span>
  </div>`;
}

function publicHeader(authenticated) {
  return html`<header class="public-header">
    <nav class="public-nav">
      <button class="brand-button" onclick="navigate('/')">${brand()}</button>
      <div class="public-links" aria-label="公共导航">
        <a href="#features">功能</a>
        <a href="#security">安全</a>
        <a href="#workflow">工作区</a>
      </div>
      <div class="public-actions">
        <button class="icon-button" onclick="toggleTheme()" title="切换主题">${state.theme === "dark" ? "日" : "夜"}</button>
        ${
          authenticated
            ? `<button class="primary" onclick="navigate('/app')">进入控制台</button>`
            : `<button class="primary" onclick="navigate('/login')">登录</button>`
        }
      </div>
    </nav>
  </header>`;
}

function landingPage(authenticated) {
  return html`<div class="public-page">
    ${publicHeader(authenticated)}
    <main>
      <section class="hero-section">
        <div class="hero-copy">
          <div class="eyebrow"><span class="pulse-dot"></span> 在线服务器管理第一阶段</div>
          <h1>浏览器里的 SSH 终端与 RDP 桌面</h1>
          <p>
            面向 Linux 与 Windows 服务器的统一连接工作台。凭据只在服务端加密保存，
            浏览器只负责终端、桌面渲染和输入事件。
          </p>
          <div class="hero-actions">
            ${
              authenticated
                ? `<button class="primary hero-button" onclick="navigate('/app')">进入控制台 <span>→</span></button>`
                : `<button class="primary hero-button" onclick="navigate('/login')">登录控制台 <span>→</span></button>`
            }
            <button class="outline hero-button" onclick="document.querySelector('#features').scrollIntoView({ behavior: 'smooth' })">查看能力</button>
          </div>
          <div class="support-row" aria-label="连接能力">
            <span>SSH PTY</span>
            <span>Guacamole RDP</span>
            <span>录屏审计</span>
            <span>文件传输</span>
          </div>
        </div>
        <div class="hero-demo" aria-label="连接工作区预览">
          <div class="demo-topbar">
            <span class="window-dot red"></span>
            <span class="window-dot yellow"></span>
            <span class="window-dot green"></span>
            <span class="demo-title">session://rdp/sess_live</span>
          </div>
          <div class="demo-screen">
            <div class="demo-sidebar">
              <span></span><span></span><span></span><span></span>
            </div>
            <div class="demo-main">
              <div class="demo-terminal">
                <code>$ ssh ubuntu@server</code>
                <code>Welcome to Ubuntu 24.04 LTS</code>
                <code>$ systemctl status nginx</code>
                <code class="ok">active (running)</code>
              </div>
              <div class="demo-rdp">
                <div class="rdp-window"></div>
                <div class="rdp-window small"></div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="landing-stats" id="features">
        ${publicStat("SSH", "浏览器 WebSocket 到服务端 SSH PTY，支持密码、私钥与 passphrase。")}
        ${publicStat("RDP", "Go tunnel 接入 guacd，前端只渲染桌面与键鼠输入。")}
        ${publicStat("审计", "会话、断开、录屏下载与关键操作写入审计日志。")}
      </section>

      <section class="feature-band" id="security">
        <div>
          <span class="section-label">Security Boundary</span>
          <h2>登录后才进入服务器资产区</h2>
          <p>公开首页不展示服务器列表、凭据、会话或审计日志。所有连接 API、WebSocket 与录屏下载都需要有效管理员会话。</p>
        </div>
        <div class="feature-list">
          <span>HttpOnly Cookie 会话</span>
          <span>凭据不下发浏览器</span>
          <span>AES-GCM 本地加密存储</span>
          <span>连接操作审计</span>
        </div>
      </section>

      <section class="workflow-band" id="workflow">
        <div class="workflow-item"><span>1</span><strong>登记服务器</strong><p>记录主机、系统、SSH/RDP 端口与分组。</p></div>
        <div class="workflow-item"><span>2</span><strong>保存凭据</strong><p>密码、私钥、域账号只在后端加密保存。</p></div>
        <div class="workflow-item"><span>3</span><strong>打开工作区</strong><p>SSH 与 RDP 全屏连接，顶部保留状态与断开操作。</p></div>
      </section>
    </main>
  </div>${toastView()}`;
}

function publicStat(title, body) {
  return html`<article class="public-stat">
    <span>${escapeHTML(title)}</span>
    <p>${escapeHTML(body)}</p>
  </article>`;
}

function signInPage() {
  return html`<div class="auth-page">
    <button class="auth-brand" onclick="navigate('/')">${brand()}</button>
    <main class="auth-card">
      <div class="auth-heading">
        <span class="section-label">Admin Console</span>
        <h1>登录</h1>
        <p>登录后查看服务器列表、凭据、连接会话与审计记录。</p>
      </div>
      <form class="auth-form" onsubmit="login(event)">
        <label>
          <span>用户名</span>
          <input name="username" autocomplete="username" placeholder="admin" required />
        </label>
        <label>
          <span>密码</span>
          <input name="password" type="password" autocomplete="current-password" placeholder="请输入管理员密码" required />
        </label>
        <button class="primary wide" type="submit">登录控制台</button>
      </form>
      <div class="auth-footnote">默认账号可通过 SERVERMANAGER_ADMIN_USER / SERVERMANAGER_ADMIN_PASSWORD 修改。</div>
    </main>
  </div>${toastView()}`;
}

async function login(event) {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  const data = Object.fromEntries(new FormData(event.target).entries());
  try {
    const res = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
    });
    state.auth = res.user;
    await refresh({ silent: true });
    navigate("/app");
    toast("已登录");
  } catch (err) {
    toast(err.message);
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } catch (_) {
    // Logout should still clear local state if the server session is already gone.
  }
  clearPrivateState();
  state.auth = null;
  navigate("/");
}

function appShell() {
  return html`<div class="app-shell">
    <aside class="sidebar">
      <button class="brand-button sidebar-brand" onclick="navigate('/')">${brand()}</button>
      <nav class="nav">
        ${navButton("overview", "总览", "⌘")}
        ${navButton("servers", "服务器", ">_")}
        ${navButton("credentials", "凭据", "key")}
        ${navButton("sessions", "会话", "rdp")}
        ${navButton("audit", "审计", "log")}
      </nav>
      <div class="sidebar-footer">
        <span class="muted small">guacd</span>
        <strong>${escapeHTML(state.guacd?.address || "未连接")}</strong>
      </div>
    </aside>
    <main class="main">
      <header class="app-header">
        <div>
          <div class="breadcrumb">ServerManager / ${escapeHTML(viewTitle())}</div>
          <h1>${escapeHTML(viewTitle())}</h1>
        </div>
        <div class="header-actions">
          <button class="outline" onclick="refresh()">刷新</button>
          <button class="outline" onclick="openModal('credential')">添加凭据</button>
          <button class="primary" onclick="openModal('server')">添加服务器</button>
          <button class="icon-button" onclick="toggleTheme()" title="切换主题">${state.theme === "dark" ? "日" : "夜"}</button>
          <button class="profile-chip" onclick="logout()" title="退出登录">${escapeHTML(state.auth?.username || "admin")}</button>
        </div>
      </header>
      <section class="content">${view()}</section>
    </main>
  </div>
  ${modalView()}
  ${toastView()}`;
}

function navButton(view, label, icon) {
  return html`<button class="${state.view === view ? "active" : ""}" onclick="setView('${view}')">
    <span class="nav-icon">${escapeHTML(icon)}</span>
    <span>${escapeHTML(label)}</span>
  </button>`;
}

function setView(view) {
  state.view = view;
  localStorage.setItem("servermanager:view", view);
  render();
}

function viewTitle() {
  return {
    overview: "总览",
    servers: "服务器",
    credentials: "凭据",
    sessions: "连接会话",
    audit: "审计日志",
  }[state.view];
}

function view() {
  if (state.view === "servers") return serversView();
  if (state.view === "credentials") return credentialsView();
  if (state.view === "sessions") return sessionsView();
  if (state.view === "audit") return auditView();
  return overviewView();
}

function overviewView() {
  const active = state.sessions.filter((s) => s.status === "active").length;
  const recordings = state.sessions.filter((s) => s.recording_path).length;
  return html`
    <section class="setup-card">
      <div class="setup-copy">
        <span class="section-label">Connection Workspace</span>
        <h2>从服务器资产直接进入 SSH 或 RDP</h2>
        <p>第一阶段专注在线连接：登记服务器和凭据后，在服务器列表里打开全屏终端或桌面工作区。</p>
      </div>
      <div class="setup-actions">
        <button class="outline" onclick="setView('credentials')">管理凭据</button>
        <button class="primary" onclick="setView('servers')">打开服务器列表</button>
      </div>
    </section>
    <section class="stat-grid">
      ${statCard("服务器", state.servers.length, "已登记 Linux / Windows 主机", "srv")}
      ${statCard("凭据", state.credentials.length, "SSH 密码、私钥与 RDP 账号", "key")}
      ${statCard("活跃会话", active, "当前仍在运行的连接", "on")}
      ${statCard("录屏索引", recordings, "RDP 原始录屏目录", "rec")}
    </section>
    <section class="panel-grid">
      <div class="panel">
        <div class="panel-header"><h2>最近会话</h2><button class="ghost" onclick="setView('sessions')">查看全部</button></div>
        ${sessionsTable(state.sessions.slice(-6).reverse())}
      </div>
      <div class="panel">
        <div class="panel-header"><h2>快速服务器</h2><button class="ghost" onclick="setView('servers')">管理</button></div>
        ${serverMiniList()}
      </div>
    </section>`;
}

function statCard(label, value, desc, icon) {
  return html`<article class="stat-card">
    <div class="stat-card-top">
      <span>${escapeHTML(label)}</span>
      <span class="stat-icon">${escapeHTML(icon)}</span>
    </div>
    <strong>${escapeHTML(value)}</strong>
    <p>${escapeHTML(desc)}</p>
  </article>`;
}

function serverMiniList() {
  if (!state.servers.length) {
    return emptyState("还没有服务器", "添加第一台服务器后，可以在这里快速发起连接。");
  }
  return html`<div class="mini-list">
    ${state.servers.slice(0, 6).map((s) => html`
      <div class="mini-row">
        <span><strong>${escapeHTML(s.name)}</strong><em>${escapeHTML(s.host)}</em></span>
        <span class="row-actions">
          <button class="tiny" onclick="openConnect('ssh','${s.id}')">SSH</button>
          <button class="tiny" onclick="openConnect('rdp','${s.id}')">RDP</button>
        </span>
      </div>`).join("")}
  </div>`;
}

function serversView() {
  return html`<div class="panel">
    <div class="panel-header">
      <div><h2>服务器资产</h2><p>登录后可见，连接动作会写入审计日志。</p></div>
      <button class="primary" onclick="openModal('server')">添加服务器</button>
    </div>
    ${
      state.servers.length
        ? html`<div class="table-wrap"><table>
            <thead><tr><th>名称</th><th>地址</th><th>系统</th><th>端口</th><th>分组</th><th></th></tr></thead>
            <tbody>
              ${state.servers.map((s) => html`
                <tr>
                  <td><strong>${escapeHTML(s.name)}</strong><div class="muted">${escapeHTML(s.description || "无描述")}</div></td>
                  <td><code>${escapeHTML(s.host)}</code></td>
                  <td>${badge(osLabel(s.os), s.os === "windows" ? "info" : "neutral")}</td>
                  <td>SSH ${escapeHTML(s.ssh_port || 22)} / RDP ${escapeHTML(s.rdp_port || 3389)}</td>
                  <td>${escapeHTML(s.group || "-")}</td>
                  <td class="row-actions">
                    <button class="primary tiny" onclick="openConnect('ssh','${s.id}')">SSH</button>
                    <button class="tiny" onclick="openConnect('rdp','${s.id}')">RDP</button>
                  </td>
                </tr>`).join("")}
            </tbody>
          </table></div>`
        : emptyState("还没有服务器", "添加服务器后，SSH/RDP 入口会出现在列表右侧。")
    }
  </div>`;
}

function credentialsView() {
  return html`<div class="panel">
    <div class="panel-header">
      <div><h2>凭据库</h2><p>敏感字段加密保存在服务端，API 响应不会返回明文。</p></div>
      <button class="primary" onclick="openModal('credential')">添加凭据</button>
    </div>
    ${
      state.credentials.length
        ? html`<div class="table-wrap"><table>
            <thead><tr><th>名称</th><th>类型</th><th>用户名</th><th>域 / 工作组</th><th>创建时间</th></tr></thead>
            <tbody>
              ${state.credentials.map((c) => html`
                <tr>
                  <td><strong>${escapeHTML(c.name)}</strong></td>
                  <td>${badge(credentialTypeLabel(c.type), "neutral")}</td>
                  <td>${escapeHTML(c.username)}</td>
                  <td>${escapeHTML(c.domain || "-")}</td>
                  <td>${formatDate(c.created_at)}</td>
                </tr>`).join("")}
            </tbody>
          </table></div>`
        : emptyState("还没有凭据", "添加 SSH 或 RDP 凭据后才能发起连接。")
    }
  </div>`;
}

function sessionsView() {
  return html`<div class="panel">
    <div class="panel-header"><div><h2>连接会话</h2><p>包含协议、目标服务器、状态、来源 IP 与录屏索引。</p></div></div>
    ${sessionsTable(state.sessions.slice().reverse())}
  </div>`;
}

function sessionsTable(sessions) {
  if (!sessions.length) return emptyState("暂无连接会话", "从服务器列表发起 SSH 或 RDP 后会出现在这里。");
  return html`<div class="table-wrap"><table>
    <thead><tr><th>协议</th><th>服务器</th><th>状态</th><th>来源</th><th>开始时间</th><th>录屏</th><th></th></tr></thead>
    <tbody>
      ${sessions.map((s) => html`
        <tr>
          <td>${badge(String(s.protocol).toUpperCase(), s.protocol === "rdp" ? "info" : "neutral")}</td>
          <td><strong>${escapeHTML(serverName(s.server_id))}</strong><div class="muted">${escapeHTML(s.id)}</div></td>
          <td>${statusBadge(s.status)}</td>
          <td>${escapeHTML(s.client_ip || "-")}</td>
          <td>${formatDate(s.started_at)}</td>
          <td>${s.recording_path ? `${escapeHTML(s.recording_size || 0)} bytes` : "-"}</td>
          <td class="row-actions">
            ${s.recording_path ? `<button class="tiny" onclick="downloadRecording('${s.id}')">下载录屏</button>` : ""}
            <button class="tiny" onclick="closeSession('${s.id}')">关闭</button>
          </td>
        </tr>`).join("")}
    </tbody>
  </table></div>`;
}

function auditView() {
  return html`<div class="panel">
    <div class="panel-header"><div><h2>审计日志</h2><p>连接、断开、凭据创建、录屏访问都会记录。</p></div></div>
    ${
      state.audit_logs.length
        ? html`<div class="table-wrap"><table>
            <thead><tr><th>时间</th><th>动作</th><th>目标</th><th>协议</th><th>来源</th><th>详情</th></tr></thead>
            <tbody>
              ${state.audit_logs.slice().reverse().map((a) => html`
                <tr>
                  <td>${formatDate(a.created_at)}</td>
                  <td><code>${escapeHTML(a.action)}</code></td>
                  <td>${escapeHTML(a.target_id || "-")}</td>
                  <td>${escapeHTML(a.protocol || "-")}</td>
                  <td>${escapeHTML(a.client_ip || "-")}</td>
                  <td>${escapeHTML(a.detail || "")}</td>
                </tr>`).join("")}
            </tbody>
          </table></div>`
        : emptyState("暂无审计日志", "登录与连接操作会逐步写入这里。")
    }
  </div>`;
}

function emptyState(title, body) {
  return html`<div class="empty-state"><strong>${escapeHTML(title)}</strong><p>${escapeHTML(body)}</p></div>`;
}

function badge(label, tone = "neutral") {
  return `<span class="badge ${tone}">${escapeHTML(label)}</span>`;
}

function statusBadge(status) {
  const tone = status === "active" ? "success" : status === "failed" ? "danger" : status === "pending" ? "warning" : "neutral";
  return badge(statusLabel(status), tone);
}

function statusLabel(status) {
  return { pending: "等待中", active: "活跃", closed: "已关闭", failed: "失败" }[status] || status;
}

function osLabel(os) {
  return { linux: "Linux", windows: "Windows" }[os] || os || "-";
}

function credentialTypeLabel(type) {
  return {
    ssh_password: "SSH 密码",
    ssh_key: "SSH 私钥",
    rdp_password: "RDP 密码",
  }[type] || type;
}

function serverName(id) {
  return state.servers.find((item) => item.id === id)?.name || id || "-";
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString("zh-CN", { hour12: false });
}

function openModal(type) {
  state.modal = { type };
  render();
}

function closeModal() {
  state.modal = null;
  render();
}

function modalView() {
  if (!state.modal) return "";
  if (state.modal.type === "credential") return credentialModal();
  if (state.modal.type === "connect") return connectModal();
  return serverModal();
}

function serverModal() {
  return html`<div class="modal-backdrop" onclick="backdropClose(event)">
    <section class="modal">
      <div class="modal-header">
        <div><h2>添加服务器</h2><p>保存主机基础信息后即可绑定凭据发起连接。</p></div>
        <button class="icon-button" onclick="closeModal()">×</button>
      </div>
      <form class="modal-body form-grid" onsubmit="createServer(event)">
        ${field("name", "名称", "", "生产网关")}
        ${field("host", "主机地址", "", "10.0.0.12 / example.com")}
        <label class="field"><span>系统</span><select name="os"><option value="linux">Linux</option><option value="windows">Windows</option></select></label>
        ${field("group", "分组", "", "default")}
        ${field("ssh_port", "SSH 端口", "22", "", "number")}
        ${field("rdp_port", "RDP 端口", "3389", "", "number")}
        <label class="field full"><span>描述</span><textarea name="description" placeholder="用途、环境、负责人等"></textarea></label>
        <div class="modal-actions full">
          <button type="button" class="outline" onclick="closeModal()">取消</button>
          <button class="primary" type="submit">保存服务器</button>
        </div>
      </form>
    </section>
  </div>`;
}

function credentialModal() {
  return html`<div class="modal-backdrop" onclick="backdropClose(event)">
    <section class="modal">
      <div class="modal-header">
        <div><h2>添加凭据</h2><p>明文只在提交时发送一次，服务端加密落盘。</p></div>
        <button class="icon-button" onclick="closeModal()">×</button>
      </div>
      <form class="modal-body form-grid" onsubmit="createCredential(event)">
        ${field("name", "名称", "", "root-key / windows-admin")}
        <label class="field"><span>类型</span><select name="type"><option value="ssh_password">SSH 密码</option><option value="ssh_key">SSH 私钥</option><option value="rdp_password">RDP 密码</option></select></label>
        ${field("username", "用户名", "", "root / ubuntu / Administrator")}
        ${field("domain", "域 / 工作组", "", "可选")}
        ${field("password", "密码", "", "可选", "password")}
        ${field("passphrase", "私钥 passphrase", "", "可选", "password")}
        <label class="field full"><span>私钥</span><textarea name="private_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
        <div class="modal-actions full">
          <button type="button" class="outline" onclick="closeModal()">取消</button>
          <button class="primary" type="submit">保存凭据</button>
        </div>
      </form>
    </section>
  </div>`;
}

function connectModal() {
  const server = state.servers.find((item) => item.id === state.modal.serverID);
  const protocol = state.modal.protocol;
  const credentials = compatibleCredentials(protocol);
  return html`<div class="modal-backdrop" onclick="backdropClose(event)">
    <section class="modal compact">
      <div class="modal-header">
        <div><h2>连接到 ${escapeHTML(server?.name || "服务器")}</h2><p>${protocol.toUpperCase()} 会话将以全屏工作区打开。</p></div>
        <button class="icon-button" onclick="closeModal()">×</button>
      </div>
      ${
        credentials.length
          ? html`<form class="modal-body form-stack" onsubmit="startConnection(event)">
              <input type="hidden" name="protocol" value="${protocol}" />
              <input type="hidden" name="server_id" value="${escapeHTML(state.modal.serverID)}" />
              <label class="field"><span>凭据</span><select name="credential_id">
                ${credentials.map((item) => `<option value="${item.id}">${escapeHTML(item.name)} (${escapeHTML(item.username)})</option>`).join("")}
              </select></label>
              <div class="connect-summary">
                <span>${escapeHTML(server?.host || "-")}</span>
                <span>${protocol === "ssh" ? `SSH ${server?.ssh_port || 22}` : `RDP ${server?.rdp_port || 3389}`}</span>
                <span>${protocol === "rdp" ? "启用录屏目录" : "PTY 终端"}</span>
              </div>
              <div class="modal-actions">
                <button type="button" class="outline" onclick="closeModal()">取消</button>
                <button class="primary" type="submit">开始连接</button>
              </div>
            </form>`
          : html`<div class="modal-body">${emptyState(`没有可用的 ${protocol.toUpperCase()} 凭据`, "请先创建对应类型的凭据，再发起连接。")}<div class="modal-actions"><button class="primary" onclick="openModal('credential')">添加凭据</button></div></div>`
      }
    </section>
  </div>`;
}

function backdropClose(event) {
  if (event.target.classList.contains("modal-backdrop")) closeModal();
}

function field(name, label, value = "", placeholder = "", type = "text") {
  return html`<label class="field">
    <span>${escapeHTML(label)}</span>
    <input name="${escapeHTML(name)}" type="${escapeHTML(type)}" value="${escapeHTML(value)}" placeholder="${escapeHTML(placeholder)}" />
  </label>`;
}

async function createServer(event) {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.ssh_port = Number(data.ssh_port || 22);
  data.rdp_port = Number(data.rdp_port || 3389);
  try {
    await api("/api/servers", { method: "POST", body: JSON.stringify(data) });
    state.modal = null;
    await refresh({ silent: true });
    toast("服务器已添加");
  } catch (err) {
    toast(err.message);
  } finally {
    button.disabled = false;
  }
}

async function createCredential(event) {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  const data = Object.fromEntries(new FormData(event.target).entries());
  try {
    await api("/api/credentials", { method: "POST", body: JSON.stringify(data) });
    state.modal = null;
    await refresh({ silent: true });
    toast("凭据已添加");
  } catch (err) {
    toast(err.message);
  } finally {
    button.disabled = false;
  }
}

function compatibleCredentials(protocol) {
  return state.credentials.filter((c) =>
    protocol === "ssh"
      ? c.type === "ssh_password" || c.type === "ssh_key"
      : c.type === "rdp_password",
  );
}

function openConnect(protocol, serverID) {
  state.modal = { type: "connect", protocol, serverID };
  render();
}

async function startConnection(event) {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  const data = Object.fromEntries(new FormData(event.target).entries());
  try {
    if (data.protocol === "ssh") {
      await startSSH(data.server_id, data.credential_id);
    } else {
      await startRDP(data.server_id, data.credential_id);
    }
  } catch (err) {
    toast(err.message);
  } finally {
    button.disabled = false;
  }
}

async function startSSH(serverID, credentialID) {
  const session = await api("/api/connections/ssh", {
    method: "POST",
    body: JSON.stringify({
      server_id: serverID,
      credential_id: credentialID,
      cols: 120,
      rows: 32,
      term: "xterm-256color",
    }),
  });
  state.modal = null;
  state.workspace = { type: "ssh", session, status: "connecting" };
  render();
  requestAnimationFrame(() => connectSSH(session));
}

async function startRDP(serverID, credentialID) {
  const width = Math.max(1024, window.innerWidth);
  const height = Math.max(680, window.innerHeight - 52);
  const session = await api("/api/connections/rdp", {
    method: "POST",
    body: JSON.stringify({
      server_id: serverID,
      credential_id: credentialID,
      width,
      height,
      dpi: 96,
    }),
  });
  state.modal = null;
  state.workspace = { type: "rdp", session, status: "connecting" };
  render();
  requestAnimationFrame(() => connectRDP(session));
}

function renderWorkspace() {
  const session = state.workspace.session;
  app.innerHTML = html`<div class="workspace">
    <div class="workspace-toolbar">
      <div class="workspace-title">
        <strong>${escapeHTML(session.protocol.toUpperCase())}</strong>
        <span>${escapeHTML(serverName(session.server_id))}</span>
        ${badge(state.workspace.status || session.status || "pending", state.workspace.status === "connected" ? "success" : "neutral")}
        ${session.protocol === "rdp" ? badge("录屏中", "danger") : ""}
      </div>
      <div class="workspace-actions">
        ${session.protocol === "rdp" ? '<button class="outline" onclick="sendClipboard()">剪贴板</button><button class="outline" onclick="uploadRDPFile()">上传文件</button>' : ""}
        <button class="outline" onclick="leaveWorkspace()">返回控制台</button>
        <button class="danger" onclick="closeWorkspace()">断开</button>
      </div>
    </div>
    ${session.protocol === "ssh" ? '<div id="terminal" class="terminal" tabindex="0"></div>' : '<div id="rdp" class="rdp-stage"></div>'}
  </div>${toastView()}`;
}

function connectSSH(session) {
  const terminalEl = document.querySelector("#terminal");
  if (!terminalEl) return;

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
    const term = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: "Cascadia Mono, JetBrains Mono, Consolas, monospace",
      fontSize: 13,
      theme: { background: "#030305", foreground: "#d4d4d8" },
    });
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
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };
    socket.onopen = () => window.onresize();
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
  }

  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === "ready") {
      state.workspace.status = "connected";
      writeOutput("Connected.\n");
    }
    if (msg.type === "stdout" || msg.type === "stderr") writeOutput(base64ToText(msg.data));
    if (msg.type === "error") writeOutput(`\n[error] ${msg.data}\n`);
  };
  socket.onclose = () => {
    state.workspace.status = "disconnected";
    writeOutput("\n[disconnected]\n");
  };
}

function connectRDP(session) {
  const container = document.querySelector("#rdp");
  if (!container) return;
  if (!window.Guacamole) {
    container.innerHTML = '<div class="workspace-error">缺少 /vendor/guacamole-common.min.js，请放置 guacamole-common-js 后重新连接。</div>';
    return;
  }

  const proto = location.protocol === "https:" ? "wss" : "ws";
  const width = Math.max(1024, window.innerWidth);
  const height = Math.max(680, window.innerHeight - 52);
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

  client.onstatechange = (stateCode) => {
    if (stateCode === 3) state.workspace.status = "connected";
    if (stateCode === 5) state.workspace.status = "disconnected";
  };
  client.onerror = (err) => toast(err.message || "RDP 连接失败");
  window.onresize = () => {
    if (typeof client.sendSize === "function") client.sendSize(window.innerWidth, window.innerHeight - 52);
  };
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
  toast("剪贴板已发送");
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
  try {
    await api(`/api/connections/${id}/close`, { method: "POST", body: "{}" });
    await refresh({ silent: true });
    toast("会话已关闭");
  } catch (err) {
    toast(err.message);
  }
}

function leaveWorkspace() {
  state.workspace = null;
  window.onresize = null;
  refresh({ silent: true });
}

async function closeWorkspace() {
  const workspace = state.workspace;
  if (workspace?.socket) workspace.socket.close();
  if (workspace?.client) workspace.client.disconnect();
  if (workspace?.session) await closeSession(workspace.session.id);
  state.workspace = null;
  window.onresize = null;
  await refresh({ silent: true });
}

function toastView() {
  return state.toast ? `<div class="toast">${escapeHTML(state.toast)}</div>` : "";
}

init();
