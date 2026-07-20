const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const profile = {
  name: "Aarav Menon",
  role: "Incident Commander",
  organization: "National Grid Operations Centre",
  team: "SOC Response Cell",
  email: "aarav.menon@ngoc.gov.in",
  device: "NGOC-SOC-EDGE-07",
  apiKey: "trata_live_8K9X_Q2N4_P7RM"
};

const GOOGLE_CLIENT_ID = "";
const LOCAL_USERNAME = "trata.admin";
const LOCAL_PASSWORD = "trata@2026";

const state = {
  route: "home",
  dark: localStorage.getItem("trataTheme") !== "light",
  loggedIn: localStorage.getItem("trataOAuth") === "connected",
  keyVisible: false,
  suspicious: false,
  selected: { packets: 0, logs: 0, files: 0 },
  graphResize: null,
  proxy: [
    { ip: "10.24.50.12", status: "Allowed", reason: "Signed backup replication endpoint", suggested: false },
    { ip: "103.27.9.44", status: "Allowed", reason: "Mutual TLS partner endpoint", suggested: false },
    { ip: "185.199.108.153", status: "Blocked", reason: "Historical C2 indicator, retained policy", suggested: false },
    { ip: "45.83.64.21", status: "Blocked", reason: "Historical reconnaissance source", suggested: false }
  ]
};

function floorToTen(date) {
  const copy = new Date(date);
  copy.setSeconds(0, 0);
  copy.setMinutes(Math.floor(copy.getMinutes() / 10) * 10);
  return copy;
}

function pad(value) {
  return String(value).padStart(2, "0");
}

function displayTime(date) {
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function fileTime(date) {
  return `${pad(date.getDate())}_${pad(date.getMonth() + 1)}_${String(date.getFullYear()).slice(2)}_${pad(date.getHours())}_${pad(date.getMinutes())}`;
}

const endTime = floorToTen(new Date());
const timeline = Array.from({ length: 7 }, (_, index) => new Date(endTime.getTime() - (6 - index) * 10 * 60 * 1000));
const nextSuspiciousTime = new Date(endTime.getTime() + 10 * 60 * 1000);
const startTime = new Date(endTime.getTime() - 60 * 60 * 1000);

const packets = timeline.map((time, index) => ({
  timestamp: displayTime(time),
  verdict: "Normal",
  event: ["Routine HTTPS session", "DNS resolver exchange", "Backup control heartbeat", "Identity token validation", "Policy sync", "Database health check", "Zeek flow rollover"][index],
  packets: 206 + index * 13,
  duration: `${24 + index * 3}s`,
  sourceIp: `10.24.${18 + index}.${40 + index}`,
  sourcePort: 42000 + index * 137,
  protocol: index % 2 ? "TCP" : "TLS",
  attackType: "None",
  transferred: 206 + index * 13,
  intel: "Matches the normal baseline for the current 10-minute window."
}));

const logs = timeline.map((time, index) => ({
  timestamp: displayTime(time),
  verdict: "Normal",
  event: ["Service heartbeat", "MFA policy refresh", "Kerberos ticket renewal", "Collector health check", "Admin console read", "Firewall policy checksum", "Scheduled audit close"][index],
  packets: 214 + index * 11,
  processId: 3180 + index * 37,
  generatedTimestamp: displayTime(time),
  generatedBy: ["systemd", "trata-collector", "krb5kdc", "zeek-agent", "policy-sync", "firewalld", "auditd"][index],
  command: ["systemctl status collector", "mfa-policy --refresh", "kinit --renew", "zeekctl cron", "policyctl checksum", "fwctl verify", "auditctl rotate"][index],
  yara: "No YARA attack identified",
  sigma: "No Sigma attack identified",
  intel: "The process behaviour is consistent with administrative baseline."
}));

const fileTemplates = [
  ["Policy export", "/var/log/trata/policy.json", "policy-sync", "48 KB", "No", "No"],
  ["Collector cache", "/opt/trata/cache/state.db", "trata-collector", "19 MB", "No", "No"],
  ["Signed DLL scan", "/usr/lib/security/auth.dll", "yara-scan", "276 KB", "Yes", "No"],
  ["Audit archive", "/var/audit/hourly.tar", "auditd", "82 MB", "No", "No"],
  ["Config backup", "/etc/trata/backup.yml", "backup-agent", "11 KB", "No", "No"],
  ["Certificate bundle", "/etc/ssl/certs/ngoc.pem", "cert-watch", "6 KB", "No", "No"],
  ["Service manifest", "/opt/trata/service.toml", "systemd", "4 KB", "Yes", "Yes"],
  ["Ruleset snapshot", "/etc/trata/rules/current.sig", "policy-sync", "91 KB", "No", "No"],
  ["IOC cache refresh", "/opt/trata/intel/ioc-cache.db", "trata-collector", "7 MB", "No", "No"],
  ["Quarantine index", "/var/lib/trata/quarantine.idx", "yara-scan", "33 KB", "No", "No"],
  ["Proxy allowlist sync", "/etc/trata/proxy/allowlist.yml", "policy-sync", "9 KB", "No", "No"],
  ["Service health dump", "/var/log/trata/health.json", "systemd", "14 KB", "No", "No"]
];

const fileOffsets = [0, 4, 9, 13, 18, 24, 31, 37, 43, 48, 54, 59];
const files = fileOffsets.map((offset, index) => {
  const time = new Date(startTime.getTime() + offset * 60 * 1000);
  const [event, location, parentProcess, size, executable, running] = fileTemplates[index];
  return {
    timestamp: displayTime(time),
    verdict: "Normal",
    event,
    packets: 202 + index * 9,
    location,
    parentProcess,
    size,
    yara: "No YARA attack identified",
    executable,
    running,
    intel: "File activity is expected for the host role and maintenance window."
  };
});

function suspiciousPacket() {
  return {
    timestamp: displayTime(nextSuspiciousTime),
    verdict: "Suspicious",
    event: "Outbound beacon pattern",
    packets: 287,
    duration: "41s",
    sourceIp: "10.24.18.77",
    sourcePort: 49322,
    protocol: "TLS",
    attackType: "Command and control",
    transferred: 287,
    intel: "New beacon cadence detected. Suggested proxy block: 198.51.100.42."
  };
}

function suspiciousLog() {
  return {
    timestamp: displayTime(nextSuspiciousTime),
    verdict: "Suspicious",
    event: "Encoded command execution",
    packets: 241,
    processId: 6224,
    generatedTimestamp: displayTime(nextSuspiciousTime),
    generatedBy: "powershell.exe",
    command: "powershell -enc SQBFAFgA",
    yara: "YARA: encoded_loader_probe",
    sigma: "Sigma: suspicious_encoded_command",
    intel: "Technique resembles T1059.001. Suggested proxy block: 198.51.100.42."
  };
}

function badge(value) {
  return `<span class="badge ${value === "Suspicious" ? "alert" : ""}">${value}</span>`;
}

function routeTo(route) {
  const cleanRoute = (route || "home").split("?")[0];
  state.route = $(`[data-page="${cleanRoute}"]`) ? cleanRoute : "home";
  $$(".page").forEach((page) => page.classList.toggle("active", page.dataset.page === state.route));
  $$(".nav a, .brand, .profile-card").forEach((link) => link.classList.toggle("active", link.dataset.route === state.route));
  history.replaceState(null, "", `#${state.route}`);
  window.scrollTo(0, 0);
  if (state.route === "behaviour" && state.graphResize) {
    requestAnimationFrame(state.graphResize);
  }
}

function renderTraffic() {
  const values = timeline.map((time, index) => ({
    time: displayTime(time),
    packets: packets[index]?.packets || 220,
    sessions: 52 + index * 4,
    files: 11 + index,
    verdict: packets[index]?.verdict || "Normal",
    event: packets[index]?.event || "Normal operations"
  }));
  if (state.suspicious) {
    values.push({
      time: displayTime(nextSuspiciousTime),
      packets: 287,
      sessions: 81,
      files: 19,
      verdict: "Suspicious",
      event: "Outbound beacon pattern"
    });
  }
  const max = Math.max(...values.map((item) => item.packets));
  const points = values.map((item, index) => {
    const x = values.length === 1 ? 0 : (index / (values.length - 1)) * 100;
    const y = 100 - (item.packets / max) * 86;
    return { ...item, x, y };
  });
  const polyline = points.map((point) => `${point.x},${point.y}`).join(" ");
  $("#trafficChart").innerHTML = `
    <svg class="traffic-path" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
      <polyline points="${polyline}" fill="none" stroke="#4A74A7" stroke-width="1.8" vector-effect="non-scaling-stroke"></polyline>
      <polyline points="${polyline}" fill="none" stroke="#68E1FD" stroke-width="0.8" opacity="0.75" vector-effect="non-scaling-stroke"></polyline>
    </svg>
    ${points.map((point) => `
      <button class="traffic-point ${point.verdict === "Suspicious" ? "alert" : ""}" style="left:${point.x}%; bottom:${100 - point.y}%">
        <span class="tooltip"><b>${point.time}</b><br>${point.packets} packets, ${point.sessions} sessions<br>${point.event}</span>
      </button>
      <span class="traffic-label" style="left:${point.x}%">${point.time}</span>
    `).join("")}
  `;
}

function renderRealtime() {
  const items = timeline.flatMap((time) => [
    `${fileTime(time)}.log`,
    `${fileTime(time)}.pcap`,
    `collector_${fileTime(time)}.json`
  ]);
  if (state.suspicious) {
    items.unshift(`${fileTime(nextSuspiciousTime)}.log`, `${fileTime(nextSuspiciousTime)}.pcap`, "file.exe");
  }
  $("#realtimeData").innerHTML = items.map((item, index) => `
    <div class="data-item ${state.suspicious && index < 3 ? "alert" : ""}">
      <b>${item}</b><span>${index < 3 && state.suspicious ? "new" : "indexed"}</span>
    </div>
  `).join("");
}

function renderTable(kind, rows, bodyId, headId, query = "") {
  const columns = kind === "files"
    ? ["Timestamp", "Verdict", "Event", "Packets", "File location"]
    : ["Timestamp", "Verdict", "Event", "Packets"];
  const filtered = rows.filter((row) => Object.values(row).join(" ").toLowerCase().includes(query.toLowerCase()));
  $(`#${headId}`).innerHTML = `<tr>${columns.map((column) => `<th>${column}</th>`).join("")}</tr>`;
  $(`#${bodyId}`).innerHTML = filtered.map((row, index) => `
    <tr data-kind="${kind}" data-index="${rows.indexOf(row)}" class="${rows.indexOf(row) === state.selected[kind] ? "selected" : ""}">
      <td>${row.timestamp}</td>
      <td>${badge(row.verdict)}</td>
      <td>${row.event}</td>
      <td>${row.packets}</td>
      ${kind === "files" ? `<td>${row.location}</td>` : ""}
    </tr>
  `).join("");
}

function renderDetail(kind, rows, targetId) {
  const row = rows[state.selected[kind]];
  const fields = kind === "packets" ? [
    ["Timestamp", row.timestamp], ["Duration", row.duration], ["Source IP", row.sourceIp], ["Source port", row.sourcePort],
    ["Protocol", row.protocol], ["Attack type", row.attackType], ["Packets transferred", row.transferred]
  ] : kind === "logs" ? [
    ["Process ID", row.processId], ["Process generated timestamp", row.generatedTimestamp], ["Process generated by", row.generatedBy],
    ["Command run", row.command], ["YARA identified attack", row.yara], ["Sigma identified attack", row.sigma]
  ] : [
    ["Parent process", row.parentProcess], ["Size", row.size], ["YARA identified attack", row.yara],
    ["Location", row.location], ["Is executable", row.executable], ["Is running", row.running]
  ];
  $(`#${targetId}`).classList.add("open");
  $(`#${targetId}`).innerHTML = `
    <div class="detail-grid">${fields.map(([label, value]) => `<div class="detail-row"><span>${label}</span><b>${value}</b></div>`).join("")}</div>
    <aside class="intel-box">
      <div class="intel-row"><span>Threat intel</span><b>${row.intel}</b></div>
      <div class="intel-row"><span>MITRE ATT&CK</span><b>${row.verdict === "Suspicious" ? "T1059.001, T1071.001" : "No active technique mapped"}</b></div>
      <div class="intel-row"><span>CVE context</span><b>${row.verdict === "Suspicious" ? "No CVE required for current containment" : "No exploit correlation in this window"}</b></div>
    </aside>
  `;
}

function hideDetail(targetId) {
  const target = $(`#${targetId}`);
  target.classList.remove("open");
  target.innerHTML = "";
}

function renderProxy() {
  $("#proxyCount").textContent = state.proxy.filter((item) => item.status === "Blocked").length;
  $("#proxyList").innerHTML = state.proxy.map((item, index) => `
    <article class="panel proxy-row">
      <header><b>${item.ip}</b>${badge(item.status === "Blocked" ? "Suspicious" : "Normal")}</header>
      <small>${item.reason}${item.suggested ? " | suggested from recent suspicious activity" : ""}</small>
      <div class="proxy-actions">
        <button class="text-button" data-proxy="${index}" data-status="Allowed">Allow</button>
        <button class="text-button" data-proxy="${index}" data-status="Blocked">Block</button>
      </div>
    </article>
  `).join("");
}

function renderProfile() {
  $("#profileInitials").textContent = profile.name.split(" ").map((part) => part[0]).join("");
  $("#profileNameMini").textContent = profile.name;
  $("#profileRoleMini").textContent = profile.role;
  $("#oauthState").textContent = state.loggedIn ? "Connected" : "Sign in required";
  $("#oauthPanel").style.display = state.loggedIn ? "none" : "grid";
  const maskedKey = state.keyVisible ? profile.apiKey : "••••••••••••••••••••••••";
  $("#profileData").innerHTML = state.loggedIn ? [
    ["Name", profile.name], ["Organization", profile.organization], ["Team", profile.team], ["Role", profile.role],
    ["Email", profile.email], ["Device", profile.device]
  ].map(([label, value]) => `<div class="profile-row"><span>${label}</span><b>${value}</b></div>`).join("") + `
    <div class="collector-box">
      <div class="collector-row"><span>Collector pairing key</span><code id="collectorKey">${maskedKey}</code></div>
      <button id="toggleCollectorKey" class="text-button">${state.keyVisible ? "Hide" : "Show"}</button>
      <button id="generateCollectorKey" class="text-button">Generate key</button>
      <button id="copyCollectorKey" class="primary-action">Copy key</button>
    </div>
  ` : "";
}

function answer(message) {
  const text = message.toLowerCase();
  if (text.includes("proxy") || text.includes("block")) return state.suspicious ? "Block 198.51.100.42. It is tied to the new beacon pattern." : "No new block is suggested in the current one-hour window.";
  if (text.includes("packet")) return "Packet capture is normal across the last hour. The next 10-minute window is being watched for beacon cadence.";
  if (text.includes("sign") || text.includes("login")) return "Open Profile and sign in with Google or your organization credentials.";
  return state.suspicious ? "Suspicious activity is active. Review Packet Capture, Logs, Behaviour, and Proxy." : "Current posture is normal across packet, log, file, and proxy telemetry.";
}

function addChat(text, user = false) {
  const item = document.createElement("div");
  item.className = `message ${user ? "user" : ""}`;
  item.textContent = text;
  $("#chatLog").appendChild(item);
  $("#chatLog").scrollTop = $("#chatLog").scrollHeight;
}

function triggerSuspicious() {
  if (state.suspicious) return;
  state.suspicious = true;
  packets.push(suspiciousPacket());
  logs.push(suspiciousLog());
  state.proxy.unshift({ ip: "198.51.100.42", status: "Blocked", reason: "Suggested block from outbound beacon pattern", suggested: true });
  $("#graphState").textContent = "Suspicious edge detected";
  renderAll();
  addChat("New suspicious 10-minute window detected. Suggested proxy block added for 198.51.100.42.");
}

function renderAll() {
  renderTraffic();
  renderRealtime();
  renderTable("packets", packets, "packetBody", "packetHead", $("#packetSearch")?.value || "");
  renderTable("logs", logs, "logBody", "logHead", $("#logSearch")?.value || "");
  renderTable("files", files, "fileBody", "fileHead", $("#fileSearch")?.value || "");
  renderProxy();
  renderProfile();
  updateCountdown();
}

function updateCountdown() {
  const remaining = Math.max(0, nextSuspiciousTime.getTime() - Date.now());
  const minutes = Math.floor(remaining / 60000);
  const seconds = Math.floor((remaining % 60000) / 1000);
  $("#nextWindow").textContent = `${pad(minutes)}:${pad(seconds)}`;
  if (remaining <= 0) triggerSuspicious();
}

function bindEvents() {
  $$(".nav a, .brand, .profile-card").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      routeTo(link.dataset.route);
    });
  });
  $("#themeToggle").addEventListener("click", () => {
    state.dark = !state.dark;
    document.body.classList.toggle("dark", state.dark);
    localStorage.setItem("trataTheme", state.dark ? "dark" : "light");
    $("#themeToggle").textContent = state.dark ? "Light mode" : "Dark mode";
  });
  [["packetSearch", "packets", packets, "packetBody", "packetHead"], ["logSearch", "logs", logs, "logBody", "logHead"], ["fileSearch", "files", files, "fileBody", "fileHead"]].forEach(([input, kind, rows, body, head]) => {
    $(`#${input}`).addEventListener("input", () => {
      renderTable(kind, rows, body, head, $(`#${input}`).value);
      if (kind === "packets") hideDetail("packetDetail");
      if (kind === "logs") hideDetail("logDetail");
      if (kind === "files") hideDetail("fileDetail");
    });
  });
  ["packetBody", "logBody", "fileBody"].forEach((bodyId) => {
    $(`#${bodyId}`).addEventListener("click", (event) => {
      const row = event.target.closest("[data-kind]");
      if (!row) return;
      const kind = row.dataset.kind;
      state.selected[kind] = Number(row.dataset.index);
      renderAll();
      if (kind === "packets") renderDetail("packets", packets, "packetDetail");
      if (kind === "logs") renderDetail("logs", logs, "logDetail");
      if (kind === "files") renderDetail("files", files, "fileDetail");
    });
  });
  $("#addProxyButton").addEventListener("click", () => $("#proxyForm").classList.toggle("open"));
  $("#proxyForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const ip = $("#proxyIp").value.trim();
    if (!ip) return;
    state.proxy.unshift({ ip, status: "Blocked", reason: $("#proxyReason").value || "Manual operator block", suggested: false });
    $("#proxyIp").value = "";
    $("#proxyReason").value = "";
    renderProxy();
  });
  $("#proxyList").addEventListener("click", (event) => {
    const button = event.target.closest("[data-proxy]");
    if (!button) return;
    state.proxy[Number(button.dataset.proxy)].status = button.dataset.status;
    renderProxy();
  });
  $("#googleLogin").addEventListener("click", () => {
    const clientId = GOOGLE_CLIENT_ID;
    if (!clientId || clientId === "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com") {
      $("#oauthState").textContent = "Google sign-in unavailable";
      return;
    }
    if (window.google?.accounts?.id) {
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: () => completeLogin()
      });
      window.google.accounts.id.prompt();
      $("#oauthState").textContent = "Google sign-in opened";
      return;
    }
    sessionStorage.setItem("trataOAuthRequest", new URLSearchParams({
      client_id: clientId,
      redirect_uri: location.origin + location.pathname,
      response_type: "id_token",
      scope: "openid profile email"
    }).toString());
    $("#oauthState").textContent = "Google sign-in loading";
  });
  $("#manualLogin").addEventListener("click", (event) => {
    event.preventDefault();
    const username = $("#manualUsername").value.trim();
    const password = $("#manualPassword").value;
    if (username !== LOCAL_USERNAME || password !== LOCAL_PASSWORD) {
      $("#oauthState").textContent = "Invalid credentials";
      return;
    }
    completeLogin();
  });

  function completeLogin() {
    localStorage.setItem("trataOAuth", "connected");
    state.loggedIn = true;
    $("#oauthState").textContent = "Connected";
    renderProfile();
    history.replaceState(null, "", `#profile`);
  }
  $("#profileData").addEventListener("click", async (event) => {
    if (event.target.id === "toggleCollectorKey") {
      state.keyVisible = !state.keyVisible;
      renderProfile();
    }
    if (event.target.id === "generateCollectorKey") {
      const random = crypto.getRandomValues(new Uint32Array(3));
      profile.apiKey = `trata_live_${[...random].map((n) => n.toString(36).slice(0, 4).toUpperCase()).join("_")}`;
      state.keyVisible = false;
      renderProfile();
    }
    if (event.target.id === "copyCollectorKey") {
      await navigator.clipboard.writeText(profile.apiKey);
      event.target.textContent = "Copied";
      setTimeout(() => {
        const button = $("#copyCollectorKey");
        if (button) button.textContent = "Copy key";
      }, 900);
    }
  });
  $("#chatToggle").addEventListener("click", () => $("#chatWidget").classList.toggle("open"));
  $("#chatForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const text = $("#chatInput").value.trim();
    if (!text) return;
    addChat(text, true);
    $("#chatInput").value = "";
    setTimeout(() => addChat(answer(text)), 250);
  });
  addEventListener("hashchange", () => routeTo(location.hash.replace("#", "") || "home"));
}

function startHeroCanvas() {
  const canvas = $("#heroGraph");
  const ctx = canvas.getContext("2d");
  const points = Array.from({ length: 28 }, () => ({ x: Math.random(), y: Math.random(), vx: (Math.random() - 0.5) * 0.0006, vy: (Math.random() - 0.5) * 0.0006 }));
  function size() {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
  }
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--bg");
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    points.forEach((point, index) => {
      point.x += point.vx;
      point.y += point.vy;
      if (point.x < 0 || point.x > 1) point.vx *= -1;
      if (point.y < 0 || point.y > 1) point.vy *= -1;
      points.slice(index + 1).forEach((other) => {
        const x = point.x * canvas.width;
        const y = point.y * canvas.height;
        const ox = other.x * canvas.width;
        const oy = other.y * canvas.height;
        const distance = Math.hypot(x - ox, y - oy);
        if (distance < 180) {
          ctx.globalAlpha = 0.16;
          ctx.strokeStyle = "#DCEAF7";
          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.lineTo(ox, oy);
          ctx.stroke();
        }
      });
      ctx.globalAlpha = 0.65;
      ctx.fillStyle = index % 8 === 0 ? "#58D68D" : "#68E1FD";
      ctx.beginPath();
      ctx.arc(point.x * canvas.width, point.y * canvas.height, 2.6, 0, Math.PI * 2);
      ctx.fill();
    });
    ctx.globalAlpha = 1;
    requestAnimationFrame(draw);
  }
  size();
  addEventListener("resize", size);
  draw();
}

function startBehaviourGraph() {
  const canvas = $("#behaviourGraph");
  const ctx = canvas.getContext("2d");
  const labels = ["Aarav", "IDP", "Zeek", "Proxy", "Files", "DB-01", "OT-GW", "Edge-07", "Backup", "SOC", "DNS", "SharePoint"];
  const nodes = Array.from({ length: 42 }, (_, index) => ({
    label: labels[index] || `host-${String(index).padStart(2, "0")}`,
    x: 0.12 + Math.random() * 0.76,
    y: 0.12 + Math.random() * 0.76,
    vx: (Math.random() - 0.5) * 0.001,
    vy: (Math.random() - 0.5) * 0.001,
    important: index < labels.length
  }));
  const edges = Array.from({ length: 96 }, (_, index) => [
    index % nodes.length,
    Math.floor((index * 7 + 5) % nodes.length),
    0.35 + Math.random() * 0.65
  ]);
  let tick = 0;
  function size() {
    const box = canvas.getBoundingClientRect();
    const width = Math.max(720, box.width || canvas.parentElement.clientWidth || 900);
    const height = Math.max(520, box.height || canvas.parentElement.clientHeight || 560);
    const ratio = Math.min(devicePixelRatio || 1, 2);
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  }
  function draw() {
    const width = canvas.width / Math.min(devicePixelRatio || 1, 2);
    const height = canvas.height / Math.min(devicePixelRatio || 1, 2);
    tick += 0.01;
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--chart-bg").trim() || "#03060B";
    ctx.fillRect(0, 0, width, height);
    nodes.forEach((node) => {
      node.x += node.vx + Math.sin(tick + node.y * 6) * 0.00012;
      node.y += node.vy + Math.cos(tick + node.x * 6) * 0.00012;
      if (node.x < 0.04 || node.x > 0.96) node.vx *= -1;
      if (node.y < 0.06 || node.y > 0.94) node.vy *= -1;
    });
    edges.forEach(([a, b, weight], index) => {
      const from = nodes[a];
      const to = nodes[b];
      const alert = state.suspicious && (index === 7 || index === 29 || index === 58);
      ctx.strokeStyle = alert ? "#FF6B6B" : "#58D68D";
      ctx.globalAlpha = alert ? 0.95 : 0.12 + weight * 0.18;
      ctx.lineWidth = alert ? 2.6 : 0.8 + weight;
      ctx.beginPath();
      ctx.moveTo(from.x * width, from.y * height);
      ctx.lineTo(to.x * width, to.y * height);
      ctx.stroke();
      if (alert) {
        const px = from.x * width + (to.x - from.x) * width * ((Math.sin(tick * 5) + 1) / 2);
        const py = from.y * height + (to.y - from.y) * height * ((Math.sin(tick * 5) + 1) / 2);
        ctx.fillStyle = "#FF6B6B";
        ctx.globalAlpha = 1;
        ctx.beginPath();
        ctx.arc(px, py, 4, 0, Math.PI * 2);
        ctx.fill();
      }
    });
    nodes.forEach((node, index) => {
      ctx.globalAlpha = 1;
      ctx.fillStyle = state.suspicious && index === 7 ? "#FF6B6B" : node.important ? "#68E1FD" : "#4A74A7";
      ctx.beginPath();
      ctx.arc(node.x * width, node.y * height, state.suspicious && index === 7 ? 7 : node.important ? 5 : 3, 0, Math.PI * 2);
      ctx.fill();
      if (node.important) {
        ctx.font = "12px Inter, sans-serif";
        ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--text").trim() || "#F4F9FF";
        ctx.globalAlpha = 0.82;
        ctx.fillText(node.label, node.x * width + 8, node.y * height - 8);
      }
    });
    ctx.globalAlpha = 1;
    requestAnimationFrame(draw);
  }
  size();
  state.graphResize = size;
  addEventListener("resize", size);
  draw();
}

function init() {
  document.body.classList.toggle("dark", state.dark);
  $("#themeToggle").textContent = state.dark ? "Light mode" : "Dark mode";
  routeTo(location.hash.replace("#", "") || "home");
  renderAll();
  bindEvents();
  addChat("Current one-hour window is normal. I will flag the next suspicious window when it arrives.");
  startHeroCanvas();
  startBehaviourGraph();
  setInterval(updateCountdown, 1000);
  setTimeout(triggerSuspicious, Math.max(0, nextSuspiciousTime.getTime() - Date.now()));
  requestAnimationFrame(() => $("#loader").classList.add("hidden"));
}

init();
