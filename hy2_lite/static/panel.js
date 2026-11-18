"use strict";

const $ = (selector) => document.querySelector(selector);
const page = document.body.dataset.page;
const states = {enabled:"Enabled", disabled:"Disabled", deleted:"Deleted"};
const coverage = {valid:"Complete", partial:"Partial", missing:"No data"};
const statuses = {pending:"Pending", running:"Applying", applied:"Applied", failed:"Failed"};
const failures = {invalid_credentials:"Invalid username, password, or verification code.", login_rate_limited:"Too many attempts. Try again later.", invalid_otp:"The code is invalid or has already been used.", subscription_not_available:"Subscription unavailable.", original_user_protected:"This original account is protected.", job_already_pending:"This account already has a pending change.", invalid_new_password:"The new password must be 8 to 256 characters."};

function el(tag, value, className) {
  const item = document.createElement(tag);
  if (value !== undefined) item.textContent = value;
  if (className) item.className = className;
  return item;
}
function notify(message, failed = false) {
  const feedback = $(".feedback");
  feedback.hidden = false;
  feedback.textContent = message;
  feedback.classList.toggle("error", failed);
}
async function api(path, method = "GET", data, key) {
  const headers = {};
  if (data !== undefined) headers["Content-Type"] = "application/json";
  if (key) headers["Idempotency-Key"] = key;
  const response = await fetch("/api/v1" + path, {method, headers, body: data === undefined ? undefined : JSON.stringify(data)});
  if (response.status === 401 && page !== "login" && method === "GET") location.assign("/login");
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(failures[detail.code] || "Request failed (HTTP " + response.status + ").");
  }
  return response;
}
const read = async (path) => (await api(path)).json();
const values = (form) => Object.fromEntries(new FormData(form));
const guard = (fn) => async (event) => {
  try { await fn(event); } catch (error) { notify(error.message, true); }
};
function bind(selector, event, fn) { $(selector).addEventListener(event, guard(fn)); }
function submit(selector, fn) {
  bind(selector, "submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    if (button) button.disabled = true;
    try { await fn(event.currentTarget); }
    finally { if (button) button.disabled = false; }
  });
}
function action(label, fn) {
  const button = el("button", label);
  button.type = "button";
  button.addEventListener("click", guard(fn));
  return button;
}
function pill(label, mode = "") { return el("span", label, "pill " + mode); }
function table(target, rows, width, message = "No records") {
  target.replaceChildren();
  if (!rows.length) {
    const cell = el("td", message, "empty");
    cell.colSpan = width;
    target.append(el("tr"));
    target.firstChild.append(cell);
  }
  for (const values of rows) {
    const row = el("tr");
    for (const value of values) {
      const cell = el("td");
      if (value instanceof Node) cell.append(value);
      else cell.textContent = value ?? "—";
      row.append(cell);
    }
    target.append(row);
  }
}
function bytes(value) {
  if (value === null || value === undefined) return "—";
  if (value < 1024) return value + " B";
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4);
  return (value / 1024 ** index).toLocaleString("en-US", {maximumFractionDigits: 2}) + " " + ["B","KiB","MiB","GiB","TiB"][index];
}
function timeLabel(value) {
  return value ? new Intl.DateTimeFormat("en-US", {timeZone:"Asia/Shanghai", dateStyle:"short", timeStyle:"short"}).format(new Date(value)) : "—";
}
function dayString(value = new Date()) {
  return new Intl.DateTimeFormat("sv-SE", {timeZone:"Asia/Shanghai", year:"numeric", month:"2-digit", day:"2-digit"}).format(value);
}
function shiftDate(day, days) {
  return new Date(Date.parse(day + "T00:00:00Z") + days * 86400000).toISOString().slice(0,10);
}
function range(period, day = dayString()) {
  const midnight = (value) => value + "T00:00:00+08:00";
  if (period === "24") {
    const end = (Math.floor(Date.now() / 3600000) + 1) * 3600000;
    return [new Date(end - 86400000).toISOString(), new Date(end).toISOString(), "hour"];
  }
  if (period === "yesterday") return [midnight(shiftDate(day, -1)), midnight(day), "hour"];
  if (period === "day") return [midnight(day), midnight(shiftDate(day, 1)), "hour"];
  return [midnight(period === "month" ? day.slice(0,8) + "01" : shiftDate(day, 1 - Number(period))), midnight(shiftDate(day,1)), "day"];
}
function trafficPath(scope, subject, period, day, csv = false) {
  const [from, to, granularity] = range(period, day);
  const params = new URLSearchParams({scope, from, to, granularity});
  if (scope === "user") params.set("user_id", subject);
  if (scope === "network") params.set("interface", subject);
  return "/traffic" + (csv ? ".csv" : "") + "?" + params;
}
const total = (up, down) => up == null && down == null ? null : (up || 0) + (down || 0);
function totals(items) {
  const known = items.filter((item) => item.upload != null || item.download != null);
  return known.length ? [known.reduce((n, x) => n + (x.upload || 0), 0), known.reduce((n,x) => n + (x.download || 0), 0)] : [null,null];
}
function metric(target, label, value, note) {
  const card = el("div", undefined, "panel metric");
  card.append(el("div", label), el("strong", value));
  if (note) card.append(el("small", note));
  target.append(card);
}
function chart(target, rows) {
  target.chartObserver?.disconnect();
  target.redraw = undefined;
  target.replaceChildren();
  if (!rows.some((item) => item.coverage !== "missing")) {
    target.append(el("p", "No traffic data to plot", "empty"));
    return;
  }
  const canvas = el("canvas", undefined, "chart");
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", "Upload and download bar chart. Yellow indicates gaps in collection.");
  target.append(canvas);
  const legend = el("div", undefined, "legend");
  for (const [key, label] of [["up","Upload"],["down","Download"],["gap","Collection gap"]]) {
    const item = el("span");
    item.append(el("i", undefined, key), document.createTextNode(label));
    legend.append(item);
  }
  target.append(legend);
  const draw = () => {
    if (!canvas.isConnected) return;
    const width = canvas.clientWidth, height = canvas.clientHeight;
    if (!width) return;
    const scale = window.devicePixelRatio || 1;
    canvas.width = width * scale;
    canvas.height = height * scale;
    const context = canvas.getContext("2d");
    context.scale(scale, scale);
    const colors = getComputedStyle(document.documentElement);
    const left = 66, top = 12, bottom = height - 28, area = Math.max(1, width - left - 10);
    const highest = Math.max(1, ...rows.flatMap((row) => [row.upload ?? 0, row.download ?? 0]));
    context.font = "11px system-ui";
    for (let i = 0; i <= 4; i++) {
      const y = bottom - (bottom - top) * i / 4;
      context.fillStyle = colors.getPropertyValue("--muted");
      context.fillText(bytes(Math.round(highest * i / 4)), 0, y + 3);
      context.strokeStyle = colors.getPropertyValue("--line");
      context.beginPath(); context.moveTo(left, y); context.lineTo(width - 10, y); context.stroke();
    }
    const step = area / rows.length;
    const barWidth = Math.min(22, step * .33);
    const barGap = Math.min(3, step * .1);
    rows.forEach((row, index) => {
      const x = left + (index + .5) * step;
      if (row.coverage !== "missing") {
        const series = [
          [row.upload, "#6853ec", x - barGap / 2 - barWidth],
          [row.download, "#00988b", x + barGap / 2],
        ];
        for (const [value, color, barX] of series) {
          if (value == null) continue;
          const barHeight = value / highest * (bottom - top);
          context.fillStyle = color;
          context.fillRect(barX, bottom - barHeight, barWidth, barHeight);
        }
      }
      if (index % Math.max(1, Math.ceil(rows.length / (width < 440 ? 4 : 8))) === 0) {
        context.fillStyle = colors.getPropertyValue("--muted");
        const label = row.day?.slice(5) || timeLabel(row.hour).slice(-5);
        context.fillText(label, Math.min(x, width - context.measureText(label).width), height - 8);
      }
      if (row.coverage !== "valid") {
        context.fillStyle = "#d7a345";
        context.beginPath();
        context.arc(x, bottom + 5, 2, 0, 2 * Math.PI);
        context.fill();
      }
    });
  };
  target.chartObserver = new ResizeObserver(draw);
  target.chartObserver.observe(canvas);
  target.redraw = draw;
  draw();
}
async function download(response, name) {
  const url = URL.createObjectURL(await response.blob());
  const link = el("a"); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function setTheme(value) {
  document.documentElement.dataset.theme = value;
  try { localStorage.setItem("hy2-theme", value); } catch {}
  $(".theme").textContent = value === "dark" ? "☀" : "☾";
  for (const target of document.querySelectorAll("#dashboard-chart,#traffic-chart")) target.redraw?.();
}
bind(".theme", "click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
setTheme(document.documentElement.dataset.theme);
for (const button of document.querySelectorAll("[data-close]")) button.addEventListener("click", () => button.closest("dialog").close());

if (page === "login") {
  bind("#show-password", "click", () => {
    const input = $("#login [name=password]");
    input.type = input.type === "password" ? "text" : "password";
    $("#show-password").setAttribute("aria-label", input.type === "password" ? "Show password" : "Hide password");
  });
  submit("#login", async (form) => { await api("/session", "POST", values(form)); location.assign("/"); });
} else {
  bind("#logout", "click", async () => { await api("/session", "DELETE"); location.assign("/login"); });
}

async function listUsers(params = {}) {
  return read("/users?" + new URLSearchParams(params));
}

async function dashboard() {
  const info = await read("/dashboard");
  const system = info.system;
  const services = $("#services"), summary = $("#summary"), resources = $("#resources");
  const serviceText = (name, state) => {
    const item = el("div", name + "　");
    item.append(pill(state === "active" ? "Running" : state || "Unknown", state === "active" ? "good" : "warn"));
    services.append(item);
  };
  serviceText("sing-box", system?.stale ? "" : system?.services["sing-box.service"]);
  serviceText("Caddy", system?.stale ? "" : system?.services["caddy.service"]);
  serviceText("Collector", info.collector.status === "observed" ? "active" : info.collector.status === "stale" ? "Stale" : "");
  $("#sample-time").textContent = "China Standard Time · " + (system ? timeLabel(system.at) : "Waiting for system metrics");
  const labels = [["CPU",system?.cpu_percent == null ? "—" : system.cpu_percent + "%"],["Memory",system ? bytes(system.memory.used) + " / " + bytes(system.memory.total) : "—"],["Disk",system ? bytes(system.disk.used) + " / " + bytes(system.disk.total) : "—"],["Swap",system ? bytes(system.swap.used) + " / " + bytes(system.swap.total) : "—"],["Uptime",system ? Math.floor(system.uptime_seconds / 3600) + " hours" : "—"],["Network TX / RX",system ? bytes(system.tx_bytes_per_second) + "/s · " + bytes(system.rx_bytes_per_second) + "/s" : "—"]];
  for (const [label,value] of labels) {
    const item = el("div", label, "muted");
    item.append(el("strong",value));
    resources.append(item);
  }
  $("#scope").querySelector('[value="network"]').disabled = !system?.interface;
  let chartRequest = 0;
  const redraw = async () => {
    const request = ++chartRequest;
    const scope = $("#scope").value, period = $("#period").value;
    const result = await read(trafficPath(scope, system?.interface, period));
    if (request === chartRequest) chart($("#dashboard-chart"), result.items);
  };
  bind("#scope","change",redraw); bind("#period","change",redraw);
  await redraw();
  const [today, week, month, users] = await Promise.all([
    read(trafficPath("proxy", "", "day")), read(trafficPath("proxy", "", "7")), read(trafficPath("proxy", "", "month")), listUsers(),
  ]);
  for (const [label, data] of [["Proxy traffic today",today],["Proxy traffic, last 7 days",week],["Proxy traffic this month",month]]) {
    const [up, down] = totals(data.items);
    metric(summary,label,bytes(total(up,down)), up == null ? "No traffic collected" : "↓ " + bytes(down) + "　↑ " + bytes(up));
  }
  const active = users.items.filter((item) => item.last_active_at && Date.now() - Date.parse(item.last_active_at) <= 86400000).length;
  metric(summary,"Active users, last 24 hours",active + " / " + users.items.length + (users.has_more ? "+" : ""));
  const entries = await Promise.all(users.items.slice(0,20).map(async (user) => {
    const data = await read(trafficPath("user", user.user_id, "day"));
    return [user.display_name, total(...totals(data.items))];
  }));
  const ranked = entries.filter(([, value]) => value !== null).sort((a,b) => b[1]-a[1]).slice(0,5);
  $("#ranking").replaceChildren(...ranked.map(([name,value]) => {
    const row = el("div", undefined, "rank-row");
    const track = el("progress");
    track.max = Math.max(1, ranked[0][1]);
    track.value = value;
    track.setAttribute("aria-label", name + " traffic today");
    row.append(el("span",name),el("strong",bytes(value)),track);
    return row;
  }));
  if (!ranked.length) $("#ranking").append(el("p","No user traffic recorded today","empty"));
}

async function usersPage() {
  let selection, change, jobId = sessionStorage.getItem("account-job"), currentPage = 1, ticket = 0, createKey, poll;
  const immediate = $("#job-panel").dataset.immediate === "yes";
  const dialog = $("#user-dialog"), form = $("#user-form");
  const confirmation = $("#confirm-form").querySelector('button[type="submit"], button:not([type])');
  confirmation.textContent = immediate ? "Confirm and apply" : "Confirm request";
  function edit(user) {
    selection = user;
    createKey = crypto.randomUUID();
    form.reset();
    $("#user-form-title").textContent = user ? "Edit user" : "Add user";
    $("#user-id").textContent = user ? user.user_id + " · Added " + timeLabel(user.managed_at) : "";
    form.elements.display_name.value = user?.display_name || "";
    form.elements.remark.value = user?.remark || "";
    $("#user-help").textContent = user ? "Changes to the display name and notes apply only to the panel." :
      immediate ? "Confirmation creates the account. Reloading may interrupt existing connections." : "An operator will apply this request during maintenance.";
    form.querySelector("button.primary").textContent = !user && immediate ? "Create account" : "Save";
    dialog.showModal();
  }
  function confirm(user, operation) {
    change = {user,operation,key:crypto.randomUUID()};
    $("#confirm-title").textContent = operation + " " + user.display_name + " (" + user.user_id + ")?";
    $("#confirm-description").textContent =
      (immediate ? "The change will run after confirmation. " : "The change will run during maintenance. ") +
      "Reloading may interrupt existing connections. " +
      (user.origin === "original" ? "Original subscription files and traffic history are preserved." : "");
    $("#confirm-dialog").showModal();
  }
  async function refreshJob() {
    if (!jobId) return;
    clearTimeout(poll);
    const selected = jobId;
    const job = await read("/jobs/" + encodeURIComponent(selected));
    if (selected !== jobId) return;
    const status = job.needs_review ? "Review configuration and rollback status" :
      job.status === "pending" && job.execute_now ? "Queued" :
      job.status === "failed" && job.execute_now ? "Not applied" : statuses[job.status];
    $("#job-panel").hidden = false;
    $("#job-status").replaceChildren(
      el("div", job.user_id + " · " + status),
      el("code", job.id),
    );
    if (job.status === "applied") await refresh();
    if (job.execute_now && !job.needs_review && ["pending", "running"].includes(job.status))
      poll = setTimeout(guard(refreshJob), 1500);
  }
  async function refresh() {
    const index = ++ticket;
    const order = $("#sort").value;
    const result = await listUsers({q:$("#search").value,state:$("#state").value,sort:["active","traffic"].includes(order) ? "name" : order,page:currentPage});
    if (index !== ticket) return;
    if (!result.items.length && currentPage > 1) {
      currentPage--;
      return refresh();
    }
    const enriched = await Promise.all(result.items.map(async (user) => {
      const period = await Promise.all(["day","24","month"].map((p) => read(trafficPath("user",user.user_id,p))));
      const sums = period.map((item) => total(...totals(item.items)));
      return {user, today:sums[0], hour:total(...totals(period[1].items.slice(-1))), month:sums[2], lifetime:total(period[0].lifetime.observed_upload,period[0].lifetime.observed_download)};
    }));
    if (index !== ticket) return;
    if (order === "traffic") enriched.sort((a,b) => (b.today ?? -1) - (a.today ?? -1));
    if (order === "active") enriched.sort((a,b) => (b.user.last_active_at || "").localeCompare(a.user.last_active_at || ""));
    table($("#user-list"), enriched.map(({user,today,hour,month,lifetime}) => {
      const name = el("div", user.display_name);
      if (user.remark) name.append(el("small",user.remark));
      const operations = el("div",undefined,"row-actions");
      operations.append(action("Edit",() => edit(user)), action("Subscription",() => location.assign("/subscriptions?user=" + encodeURIComponent(user.user_id))));
      if (user.effective_state !== "deleted") operations.append(
        action(user.effective_state === "enabled" ? "Disable" : "Enable",() => confirm(user,user.effective_state === "enabled" ? "Disable" : "Enable")),
        action("Delete",() => confirm(user,"Delete")),
      );
      return [name,user.user_id,pill(states[user.effective_state],user.effective_state === "enabled" ? "good" : ""),bytes(today),bytes(hour),bytes(month),bytes(lifetime),timeLabel(user.last_active_at),operations];
    }),9);
    $("#user-prev").disabled = currentPage <= 1;
    $("#user-next").disabled = !result.has_more;
  }
  let debounce;
  bind("#search","input",() => { clearTimeout(debounce); debounce = setTimeout(guard(() => { currentPage = 1; return refresh(); }),250); });
  for (const selector of ["#sort","#state"]) bind(selector,"change",() => { currentPage = 1; return refresh(); });
  bind("#user-prev","click",() => { currentPage--; return refresh(); });
  bind("#user-next","click",() => { currentPage++; return refresh(); });
  bind("#new-user","click",() => edit(null));
  bind("#refresh-job","click",refreshJob);
  submit("#user-form", async (form) => {
    if (selection) {
      await api("/users/" + encodeURIComponent(selection.user_id),"PATCH",values(form));
      notify("User details saved.");
      await refresh();
    } else {
      const response = await api("/users","POST",{...values(form),execute_now:immediate},createKey);
      jobId = (await response.json()).id;
      sessionStorage.setItem("account-job", jobId);
      await refreshJob();
    }
    dialog.close();
  });
  submit("#confirm-form", async () => {
    const {user,operation,key} = change, path = "/users/" + encodeURIComponent(user.user_id);
    const body = {confirm_user_id:user.user_id,execute_now:immediate};
    const response = operation === "Delete" ? await api(path,"DELETE",body,key) :
      await api(path + "/state","POST",{...body,enabled:operation === "Enable"},key);
    jobId = (await response.json()).id;
    sessionStorage.setItem("account-job", jobId);
    $("#confirm-dialog").close();
    await refreshJob();
  });
  await refresh();
  if (jobId) await refreshJob();
}

async function trafficPage() {
  const user = $("#traffic-user"), date = $("#traffic-date"), period = $("#traffic-period");
  const info = await listUsers();
  const queryUser = new URLSearchParams(location.search).get("user");
  user.append(new Option("All proxy traffic",""));
  for (const item of info.items) user.append(new Option(item.display_name,item.user_id));
  if (queryUser && info.items.some((item) => item.user_id === queryUser)) user.value = queryUser;
  date.value = dayString();
  date.max = date.value;
  let sequence = 0;
  function path(csv) { return trafficPath(user.value ? "user" : "proxy", user.value, period.value, date.value || dayString(), csv); }
  async function refresh() {
    const current = ++sequence;
    const selectedUser = user.value;
    const result = await read(path(false));
    if (current !== sequence) return;
    const [up,down] = totals(result.items);
    const summary = $("#traffic-summary");
    summary.replaceChildren();
    metric(summary,"Upload in selected range",bytes(up)); metric(summary,"Download in selected range",bytes(down));
    metric(summary,"Total in selected range",bytes(total(up,down)));
    metric(summary,selectedUser ? "Last active" : "Total observed",selectedUser ? timeLabel(result.last_active_at) : bytes(total(result.lifetime.observed_upload,result.lifetime.observed_download)));
    $("#traffic-title").textContent = ["day","yesterday","24"].includes(period.value) ? "Hourly traffic" : "Daily traffic";
    chart($("#traffic-chart"),result.items);
    table($("#traffic-list"),result.items.map((row) => {
      let label = row.day || timeLabel(row.hour);
      if (row.day) label = action(row.day,() => { date.value = row.day; period.value = "day"; return refresh(); });
      return [label,bytes(row.upload),bytes(row.download),bytes(total(row.upload,row.download)),pill(coverage[row.coverage],row.coverage === "valid" ? "good" : row.coverage === "partial" ? "warn" : "")];
    }),5);
  }
  for (const field of ["#traffic-user","#traffic-period","#traffic-date"]) bind(field,"change",refresh);
  bind("#csv","click",async () => download(await api(path(true)),"hy2-traffic.csv"));
  await refresh();
}

async function subscriptionPage() {
  const result = await read("/subscriptions");
  let selected = null;
  function select(item) {
    selected = item;
    $("#subscription-name").textContent = item.display_name;
    $("#subscription-id").textContent = item.user_id;
    $("#subscription-detail").hidden = false;
    for (const button of document.querySelectorAll("[data-export]")) {
      const kind = button.dataset.export;
      const available = item.effective_state === "enabled" && (item.managed_subscription || (item.original_subscription && ["url","qr"].includes(kind)));
      button.disabled = !available;
    }
  }
  function refresh() {
    const query = $("#subscription-search").value.toLowerCase();
    table($("#subscription-list"),result.items.filter((item) => (item.display_name + " " + item.user_id).toLowerCase().includes(query)).map((item) =>
      [item.display_name,pill(item.origin === "original" ? "Original" : "Managed"),pill(states[item.effective_state],item.effective_state === "enabled" ? "good" : ""),action("View",() => select(item))]),4);
  }
  bind("#subscription-search","input",refresh);
  let qrUrl;
  $("#qr-dialog").addEventListener("close",() => { if (qrUrl) URL.revokeObjectURL(qrUrl); $("#qr-image").removeAttribute("src"); });
  for (const button of document.querySelectorAll("[data-export]")) button.addEventListener("click",guard(async () => {
    const kind = button.dataset.export, path = "/subscriptions/" + encodeURIComponent(selected.user_id) + "/export";
    const response = await api(path,"POST",{format:kind});
    if (kind === "url" || kind === "uri") {
      const result = await response.json();
      await navigator.clipboard.writeText(result[kind]);
      notify("Copied.");
    } else if (kind === "qr") {
      qrUrl = URL.createObjectURL(await response.blob());
      $("#qr-image").src = qrUrl; $("#qr-dialog").showModal();
    } else await download(response,"hy2-subscription." + kind);
  }));
  refresh();
  const target = new URLSearchParams(location.search).get("user");
  const initial = result.items.find((item) => item.user_id === target) || result.items[0];
  if (initial) select(initial);
}

async function settingsPage() {
  let auditPage = 1, totp = false;
  const info = await read("/system/collector");
  const observed = info.collector.status === "observed";
  $("#collector-status").append(pill(observed ? "Running" : info.collector.status === "stale" ? "Stale" : "No samples",observed ? "good" : "warn"));
  $("#collector-status").append(el("p","Last successful sample " + timeLabel(info.collector.last_success_at),"muted"));
  const event = info.collector.latest_event;
  $("#collector-event").textContent = event ? timeLabel(event.end) + " · " + ({collector_gap:"Collection gap",unreconciled:"Counters did not reconcile",instance_changed:"Instance reloaded",counter_reset:"Counters reset"}[event.reason] || event.reason) : "No events";
  async function audit() {
    const data = await read("/system/audit?page=" + auditPage);
    table($("#audit-list"),data.items.map((item) => [timeLabel(item.at),item.action + (item.target ? " · " + item.target : ""),({ok:"Success",applied:"Applied",denied:"Denied",failed:"Failed"}[item.result] || item.result)]),3);
    $("#audit-prev").disabled = auditPage <= 1;
    $("#audit-next").disabled = !data.has_more;
  }
  async function security() {
    const data = await read("/system/security");
    totp = data.totp_enabled;
    $("#totp-status").textContent = "TOTP two-factor authentication · " + (totp ? "Enabled" : "Disabled");
    $("#totp-action").textContent = totp ? "Disable two-factor authentication" : "Set up two-factor authentication";
  }
  async function backups() {
    const data = await read("/system/backups");
    $("#backup-status").textContent = data.last_at ? "Last backup " + timeLabel(data.last_at) : data.enabled ? "No database backups" : "Backup directory is not configured";
    $("#backup-create").disabled = !data.enabled;
  }
  for (const button of document.querySelectorAll("[data-tab]")) button.addEventListener("click",() => {
    for (const tab of document.querySelectorAll("[data-tab]")) tab.removeAttribute("aria-current");
    button.setAttribute("aria-current","true");
    document.querySelector('[data-setting="' + button.dataset.tab + '"]').scrollIntoView({block:"start",behavior:"smooth"});
  });
  submit("#password-form",async (form) => { await api("/system/password","POST",values(form)); form.reset(); notify("Password changed. Other sessions were signed out."); });
  submit("#totp-form",async (form) => {
    if (totp) {
      await api("/system/totp/disable","POST",values(form)); await security(); notify("Two-factor authentication disabled.");
    } else {
      const response = await api("/system/totp/setup","POST",values(form));
      const data = await response.json();
      $("#totp-confirm").elements.secret.value = data.secret;
      $("#totp-confirm").hidden = false;
    }
    form.reset();
  });
  submit("#totp-confirm",async (form) => {
    await api("/system/totp/confirm","POST",{otp:values(form).otp});
    form.reset(); form.hidden = true; await security(); notify("Two-factor authentication enabled.");
  });
  bind("#audit-prev","click",() => { auditPage--; return audit(); });
  bind("#audit-next","click",() => { auditPage++; return audit(); });
  bind("#backup-create","click",async () => { await api("/system/backups","POST",{}); await backups(); notify("Database backup created."); });
  await Promise.all([security(),audit(),backups()]);
}

const screens = {dashboard,users:usersPage,traffic:trafficPage,subscriptions:subscriptionPage,settings:settingsPage};
if (screens[page]) guard(screens[page])();
