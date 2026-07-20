const palette = {
  ice: "#DCEAF7",
  steel: "#4A74A7",
  navy: "#142A44",
  night: "#081426",
  cyan: "#68E1FD",
  green: "#58D68D",
  red: "#FF6B6B",
  amber: "#F6C85F"
};

const fallback = {
  profile: {
    name: "Aarav Menon",
    organisation: "National Grid Operations Centre",
    role: "Incident Commander",
    backendUrl: "http://localhost:8080"
  },
  system: {
    device: "NGOC-SOC-EDGE-07",
    ip: "10.24.18.77",
    os: "Ubuntu 24.04 LTS",
    storage: "1.8 TB NVMe, 64% used",
    ram: "64 GB DDR5, 41% used",
    network: "Zeek sensor on VLAN-17, 1.4 Gbps observed",
    baseline: "Behaviour profile stable, 97.2% confidence",
    collector: "Endpoint collector v2.6.1, signed and healthy"
  },
  dashboard: {
    scores: { yara: 91, sigma: 84, cve: 72, coverage: 88 },
    attacks: [
      ["Credential access", 17],
      ["Lateral movement", 11],
      ["Command and control", 8],
      ["Discovery", 15],
      ["Data staging", 5]
    ],
    traffic: [42, 48, 45, 54, 88, 61, 57, 122, 70, 66, 55, 49, 93, 110, 63, 58, 52, 45, 79, 86, 120, 72, 61, 50, 44, 76, 98, 69]
  },
  packets: [
    ["20:42:11", "13s", "Attacked", "C2 beacon over HTTPS", "185.199.108.153", "Blocked"],
    ["20:39:08", "31s", "Non attacked", "Routine DNS resolution", "10.24.18.41", "Allowed"],
    ["20:35:56", "48s", "Attacked", "SMB lateral movement attempt", "10.24.31.19", "Quarantined"],
    ["20:31:24", "9s", "Attacked", "Port scan against OT subnet", "45.83.64.21", "Blocked"],
    ["20:28:43", "64s", "Non attacked", "Backup replication flow", "10.24.50.12", "Allowed"]
  ],
  logs: [
    ["20:42:09", "6s", "Attacked", "Suspicious PowerShell encoded command", "10.24.18.77", "Sigma: win_ps_encoded"],
    ["20:40:17", "22s", "Attacked", "New service created remotely", "10.24.31.19", "Sigma: remote_service_creation"],
    ["20:36:55", "4s", "Non attacked", "Admin console login with MFA", "10.24.12.8", "Sigma: verified_admin_login"],
    ["20:34:26", "16s", "Attacked", "Failed Kerberos pre-auth burst", "10.24.18.33", "Sigma: kerberos_spray"],
    ["20:29:01", "11s", "Attacked", "LSASS handle request anomaly", "10.24.18.77", "Sigma: credential_dumping"]
  ],
  files: [
    ["20:41:58", "Trojanized scheduler DLL", "Resolved", "T1053.005", "YARA: apt_scheduler_loader"],
    ["20:37:20", "Packed executable in temp share", "Contained", "T1027", "YARA: upx_loader_entropy"],
    ["20:33:05", "Mimikatz signature fragment", "Resolved", "T1003.001", "YARA: credential_dump_tooling"],
    ["20:25:46", "Unsigned driver dropper", "Review", "T1068", "YARA: kernel_dropper_india_cni"],
    ["20:20:14", "Benign policy export", "Clean", "T1082", "YARA: no_match"]
  ],
  intel: [
    ["APT mapping", "T1021.002", "Remote Services: SMB Admin Shares", "Matches lateral movement from edge workstation to file server."],
    ["CVE feed", "CVE-2025-53770", "SharePoint deserialization exposure", "Public exploit pressure high, patch window recommended tonight."],
    ["CERT-In", "CIAD-2026-0718", "Government portal credential harvesting", "Indicators overlap with blocked IP 185.199.108.153."],
    ["Prediction", "T1041", "Exfiltration over C2 channel", "Likely next move if data staging is not interrupted."],
    ["KVE", "CVE-2024-3094", "Supply-chain backdoor watch", "No active hit, retained due to critical asset class."]
  ],
  proxy: [
    { ip: "185.199.108.153", url: "cdn-update-check.net", status: "Blocked", attacks: 7, reason: "C2 beacon and CERT-In indicator match" },
    { ip: "45.83.64.21", url: "scan-gw.su", status: "Blocked", attacks: 3, reason: "Repeated OT subnet reconnaissance" },
    { ip: "10.24.50.12", url: "backup-ngoc.local", status: "Allowed", attacks: 0, reason: "Signed backup replication path" },
    { ip: "103.27.9.44", url: "exam-data-sync.gov.in", status: "Allowed", attacks: 0, reason: "Mutual TLS verified partner endpoint" }
  ],
  playbook: [
    ["Isolate endpoint NGOC-SOC-EDGE-07", "Ready", "Human gate not required, blast radius is single workstation."],
    ["Block 185.199.108.153 at proxy and firewall", "Queued", "Correlated with C2 beacon and CERT-In advisory."],
    ["Revoke stale service credential svc_backup_legacy", "Ready", "Observed in failed Kerberos spray pattern."],
    ["Snapshot VM FILE-SRV-03", "Waiting", "Requires storage approval for production tier."]
  ],
  assets: [
    ["SP-CBSE-01", "High", "Public SharePoint service, 18,240 daily users, patch window pending."],
    ["FILE-SRV-03", "High", "Exam archive share with unusual SMB admin probing from VLAN-17."],
    ["OT-GW-12", "Medium", "Substation gateway, protected by proxy allowlist and read-only telemetry."],
    ["IDP-PRIMARY", "Medium", "Identity provider, Kerberos spray controls enabled and MFA healthy."]
  ],
  vulnerabilities: [
    ["CVE-2025-53770", "Critical", "Patch SP-CBSE-01, public exploit pressure and exposed service path."],
    ["CVE-2024-3094", "High", "Verify package provenance on Linux collector build hosts."],
    ["CVE-2026-21412", "High", "Rotate service account token used by legacy backup connector."],
    ["CVE-2025-29824", "Medium", "Schedule kernel patch on operator workstations within 72 hours."]
  ],
  assurance: [
    ["Audit trail", "Enabled", "Every automated action is signed with operator, policy, and evidence hash."],
    ["Human gates", "Active", "Production-tier snapshots and credential revocations require approval."],
    ["Data retention", "365 days", "Packet metadata, Sigma matches, YARA hits, and proxy decisions retained."],
    ["Compliance", "Aligned", "CERT-In incident reporting package can be exported from current case."]
  ]
};

const auditTemplates = [
  ["HIGH", "Sigma rule remote_service_creation fired on 10.24.31.19", "Mapped to T1569.002, containment queue updated."],
  ["MED", "Zeek observed JA3 hash drift from NGOC-SOC-EDGE-07", "Baseline deviation 4.8 sigma over 12-minute window."],
  ["LOW", "YARA scan completed on shared drive segment FIN-02", "No malicious file writes in the last sweep."],
  ["HIGH", "Proxy denied outbound flow to 185.199.108.153", "Prior attack history confirmed, firewall rule retained."],
  ["MED", "CVE pressure increased for SharePoint asset SP-CBSE-01", "Exploitability raised due to public PoC chatter."],
  ["INFO", "Digital twin simulation completed for lateral movement path", "Best containment point is VLAN-17 egress control."],
  ["HIGH", "Kerberos pre-auth failures crossed spray threshold", "Credential revocation playbook prepared for svc_backup_legacy."],
  ["INFO", "CERT-In advisory correlation refreshed", "Two indicators overlap with current packet history."]
];

const tableConfig = {
  packets: ["Timestamp", "Duration", "Verdict", "Attack", "IP", "Action"],
  logs: ["Timestamp", "Duration", "Verdict", "Signal", "IP", "Sigma"],
  files: ["Timestamp", "File event", "State", "MITRE ATT&CK", "YARA"],
  intel: ["Source", "Reference", "Finding", "Detail"]
};

const state = {
  data: structuredClone(fallback),
  currentTable: "packets",
  auditPaused: false,
  auditIndex: 0,
  proxy: structuredClone(fallback.proxy),
  selectedRow: fallback.packets[0]
};

const $ = (selector) => document.querySelector(selector);

if ("scrollRestoration" in history) {
  history.scrollRestoration = "manual";
}

function forceTop() {
  if (location.hash && location.hash !== "#top") {
    history.replaceState(null, "", location.pathname + location.search);
  }
  window.scrollTo(0, 0);
}

async function getJson(path, fallbackValue, timeoutMs = 900) {
  const base = localStorage.getItem("trataBackendUrl") || fallback.profile.backendUrl;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${base}${path}`, {
      headers: { "x-api-key": $("#apiKey")?.textContent || "" },
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    return payload && Object.keys(payload).length ? payload : fallbackValue;
  } catch {
    return fallbackValue;
  } finally {
    clearTimeout(timer);
  }
}

function setInitialFields() {
  $("#operatorName").value = fallback.profile.name;
  $("#organisation").value = fallback.profile.organisation;
  $("#role").value = fallback.profile.role;
  $("#backendUrl").value = localStorage.getItem("trataBackendUrl") || fallback.profile.backendUrl;
  renderProfile();
}

function renderProfile() {
  const name = $("#operatorName")?.value || fallback.profile.name;
  const role = $("#role")?.value || fallback.profile.role;
  const organisation = $("#organisation")?.value || fallback.profile.organisation;
  $("#sideName").textContent = name;
  $("#sideRole").textContent = role;
  $("#sideOrg").textContent = organisation;
  $(".avatar").textContent = name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
}

function updateClock() {
  $("#clock").textContent = new Intl.DateTimeFormat("en-IN", {
    dateStyle: "medium",
    timeStyle: "medium",
    hour12: false
  }).format(new Date());
}

function renderScores() {
  const scores = state.data.dashboard.scores || fallback.dashboard.scores;
  $("#yaraScore").textContent = scores.yara;
  $("#sigmaScore").textContent = scores.sigma;
  $("#cveScore").textContent = scores.cve;
  $("#coverageScore").textContent = scores.coverage;
  $("#heroScore").textContent = Math.round((scores.yara + scores.sigma + scores.coverage + (100 - scores.cve)) / 4);
}

function renderTraffic() {
  const chart = $("#trafficChart");
  chart.innerHTML = "";
  state.data.dashboard.traffic.forEach((value) => {
    const bar = document.createElement("div");
    bar.className = `traffic-bar ${value > 82 ? "alert" : ""}`;
    bar.style.height = `${Math.max(18, value * 1.8)}px`;
    bar.title = `${value} flows`;
    chart.appendChild(bar);
  });
}

function renderAttacks() {
  const wrap = $("#attackBars");
  wrap.innerHTML = "";
  const max = Math.max(...state.data.dashboard.attacks.map(([, count]) => count));
  state.data.dashboard.attacks.forEach(([name, count]) => {
    const row = document.createElement("div");
    row.className = "attack-row";
    row.innerHTML = `<header><b>${name}</b><span>${count}</span></header><div class="mini-bar"><i style="width:${(count / max) * 100}%"></i></div><small>${count} confirmed or prevented attempts in the current window.</small>`;
    wrap.appendChild(row);
  });
}

function renderSystem() {
  const system = state.data.system || fallback.system;
  $("#systemList").innerHTML = Object.entries(system).map(([key, value]) => `
    <div class="system-row"><span>${key.replace(/^\w/, (c) => c.toUpperCase())}</span><b>${value}</b></div>
  `).join("");
}

function severityClass(level) {
  if (level === "HIGH") return "alert";
  if (level === "MED") return "warn";
  return level === "INFO" ? "info" : "";
}

function addAuditEvent(force = false) {
  if (state.auditPaused && !force) return;
  const [level, message, detail] = auditTemplates[state.auditIndex % auditTemplates.length];
  state.auditIndex += 1;
  const time = new Date().toLocaleTimeString("en-IN", { hour12: false });
  const item = document.createElement("div");
  item.className = "audit-item";
  item.innerHTML = `<time>${time}</time><span class="badge ${severityClass(level)}">${level}</span><p>${message}<small>${detail}</small></p>`;
  $("#auditStream").prepend(item);
  [...$("#auditStream").children].slice(14).forEach((node) => node.remove());
  $("#heroSignals").textContent = (18421 + state.auditIndex * 13).toLocaleString("en-IN");
}

function renderTable() {
  const query = $("#tableSearch").value.trim().toLowerCase();
  const rows = (state.data[state.currentTable] || fallback[state.currentTable]).filter((row) =>
    row.join(" ").toLowerCase().includes(query)
  );
  $("#tableHead").innerHTML = `<tr>${tableConfig[state.currentTable].map((head) => `<th>${head}</th>`).join("")}</tr>`;
  if (!rows.some((row) => row.join("|") === state.selectedRow?.join("|"))) {
    state.selectedRow = rows[0] || fallback[state.currentTable][0];
  }
  $("#tableBody").innerHTML = rows.map((row, index) => `
    <tr class="${row.join("|") === state.selectedRow?.join("|") ? "selected" : ""}" data-row="${index}">
      ${row.map((cell) => `<td>${decorateCell(cell)}</td>`).join("")}
    </tr>
  `).join("");
  renderDetail();
}

function decorateCell(cell) {
  const text = String(cell);
  if (["Attacked", "Blocked", "Quarantined"].includes(text)) return `<span class="badge alert">${text}</span>`;
  if (["Review", "Waiting", "Contained", "Queued"].includes(text)) return `<span class="badge warn">${text}</span>`;
  if (["Allowed", "Resolved", "Clean", "Non attacked"].includes(text)) return `<span class="badge">${text}</span>`;
  return text;
}

function renderProxy() {
  $("#proxyList").innerHTML = state.proxy.map((item, index) => `
    <div class="proxy-row">
      <header><b>${item.ip}</b><span class="badge ${item.status === "Blocked" ? "alert" : ""}">${item.status}</span></header>
      <small>${item.url} | previous attacks: ${item.attacks} | ${item.reason}</small>
      <div class="proxy-actions">
        <button class="text-button" data-proxy="${index}" data-action="Allowed">Allow</button>
        <button class="text-button" data-proxy="${index}" data-action="Blocked">Block</button>
      </div>
    </div>
  `).join("");
}

function renderPlaybook() {
  $("#playbookList").innerHTML = fallback.playbook.map(([action, status, reason]) => `
    <div class="playbook-row">
      <header><b>${action}</b><span class="badge ${severityClass(status === "Ready" ? "INFO" : "MED")}">${status}</span></header>
      <small>${reason}</small>
    </div>
  `).join("");
}

function renderOperations() {
  $("#assetList").innerHTML = fallback.assets.map(([asset, risk, detail]) => `
    <div class="asset-row">
      <header><b>${asset}</b><span class="badge ${risk === "High" ? "alert" : "warn"}">${risk}</span></header>
      <small>${detail}</small>
    </div>
  `).join("");

  $("#vulnerabilityList").innerHTML = fallback.vulnerabilities.map(([cve, priority, detail]) => `
    <div class="vulnerability-row">
      <header><b>${cve}</b><span class="badge ${priority === "Critical" ? "alert" : "warn"}">${priority}</span></header>
      <small>${detail}</small>
    </div>
  `).join("");

  $("#assuranceList").innerHTML = fallback.assurance.map(([control, stateText, detail]) => `
    <div class="assurance-row">
      <header><b>${control}</b><span class="badge info">${stateText}</span></header>
      <small>${detail}</small>
    </div>
  `).join("");
}

function renderDetail() {
  const headers = tableConfig[state.currentTable];
  const row = state.selectedRow || fallback[state.currentTable][0];
  $("#detailView").innerHTML = headers.map((header, index) => `
    <div class="detail-row">
      <span>${header}</span>
      <b>${row[index] || "Not recorded"}</b>
    </div>
  `).join("");
  $("#detailState").textContent = state.currentTable === "intel" ? "threat context" : "evidence selected";
}

function addChat(message, fromUser = false) {
  const item = document.createElement("div");
  item.className = `message ${fromUser ? "user" : ""}`;
  item.textContent = message;
  $("#chatLog").appendChild(item);
  item.scrollIntoView({ block: "nearest" });
}

function answerQuestion(text) {
  const lower = text.toLowerCase();
  if (lower.includes("cve")) return "Prioritise CVE-2025-53770 first. It touches an exposed collaboration asset, has active exploit pressure, and overlaps with the current credential access chain.";
  if (lower.includes("mitre") || lower.includes("ttp")) return "The active path maps to T1110, T1003.001, T1021.002, and T1041. The strongest evidence is Kerberos spray followed by SMB admin share probing.";
  if (lower.includes("block") || lower.includes("response")) return "Keep 185.199.108.153 blocked, isolate NGOC-SOC-EDGE-07, revoke svc_backup_legacy, then snapshot FILE-SRV-03 before deeper file recovery.";
  return "Current assessment: medium-high confidence intrusion attempt, contained at egress. No evidence of completed exfiltration, but lateral movement probing needs endpoint isolation now.";
}

function bindEvents() {
  $("#generateKey").addEventListener("click", () => {
    const random = crypto.getRandomValues(new Uint32Array(3));
    $("#apiKey").textContent = `trata_live_${[...random].map((n) => n.toString(36).slice(0, 4).toUpperCase()).join("_")}`;
    $("#syncStatus").textContent = "New collector key generated. Paste it into the endpoint collector before first run.";
  });

  $("#copyKey").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("#apiKey").textContent);
    $("#syncStatus").textContent = "API key copied. Collector can now pair with this console.";
  });

  $("#profileForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    renderProfile();
    localStorage.setItem("trataBackendUrl", $("#backendUrl").value || fallback.profile.backendUrl);
    $("#syncStatus").textContent = "Sync requested. Backend enrichment is running in the background.";
    hydrate();
  });

  ["operatorName", "organisation", "role"].forEach((id) => {
    $(`#${id}`).addEventListener("input", renderProfile);
  });

  $("#pauseAudit").addEventListener("click", () => {
    state.auditPaused = !state.auditPaused;
    $("#pauseAudit").textContent = state.auditPaused ? "Resume feed" : "Pause feed";
    $("#auditRate").textContent = state.auditPaused ? "paused" : "streaming";
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((node) => node.classList.remove("active"));
      tab.classList.add("active");
      state.currentTable = tab.dataset.table;
      renderTable();
    });
  });

  $("#tableSearch").addEventListener("input", renderTable);

  $("#tableBody").addEventListener("click", (event) => {
    const rowElement = event.target.closest("[data-row]");
    if (!rowElement) return;
    const query = $("#tableSearch").value.trim().toLowerCase();
    const rows = (state.data[state.currentTable] || fallback[state.currentTable]).filter((row) =>
      row.join(" ").toLowerCase().includes(query)
    );
    state.selectedRow = rows[Number(rowElement.dataset.row)];
    renderTable();
  });

  $("#markEvidence").addEventListener("click", () => {
    $("#detailState").textContent = "reviewed";
    addAuditEvent(true);
  });

  $("#promoteEvidence").addEventListener("click", () => {
    $("#detailState").textContent = "case evidence";
    $("#heroActions").textContent = Number($("#heroActions").textContent) + 1;
    addChat("Selected evidence promoted to case NGOC-APT-2026-0719 with current telemetry context attached.");
  });

  $("#proxyList").addEventListener("click", (event) => {
    const button = event.target.closest("[data-proxy]");
    if (!button) return;
    const item = state.proxy[Number(button.dataset.proxy)];
    item.status = button.dataset.action;
    addAuditEvent(true);
    $("#syncStatus").textContent = `${item.ip} moved to ${item.status.toLowerCase()} proxy policy.`;
    renderProxy();
  });

  $("#runPlaybook").addEventListener("click", () => {
    $("#playbookState").textContent = "playbook executed";
    $("#heroActions").textContent = Number($("#heroActions").textContent) + 3;
    addAuditEvent(true);
    addChat("Containment playbook executed for edge workstation, blocked C2 IP, and revoked legacy service credential.");
  });

  $("#simulateIncident").addEventListener("click", () => {
    const traffic = state.data.dashboard.traffic;
    traffic.push(128);
    traffic.shift();
    state.data.logs.unshift(["Now", "8s", "Attacked", "Suspicious service ticket request spike", "10.24.18.33", "Sigma: kerberos_spray"]);
    state.auditIndex += 1;
    renderTraffic();
    addAuditEvent(true);
    $("#trafficState").textContent = "new suspicious flow injected";
  });

  $("#chatForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const text = $("#chatInput").value.trim();
    if (!text) return;
    addChat(text, true);
    $("#chatInput").value = "";
    setTimeout(() => addChat(answerQuestion(text)), 450);
  });
}

async function hydrate() {
  const [system, dashboard, packets, logs, files, intel, proxy] = await Promise.all([
    getJson("/api/system", fallback.system),
    getJson("/api/dashboard", fallback.dashboard),
    getJson("/api/packets", fallback.packets),
    getJson("/api/logs", fallback.logs),
    getJson("/api/files", fallback.files),
    getJson("/api/intel", fallback.intel),
    getJson("/api/proxy", fallback.proxy)
  ]);
  state.data = { ...state.data, system, dashboard, packets, logs, files, intel };
  state.proxy = Array.isArray(proxy) ? proxy : fallback.proxy;
  $("#systemSource").textContent = system === fallback.system ? "Endpoint telemetry" : "Backend telemetry";
  renderScores();
  renderTraffic();
  renderAttacks();
  renderSystem();
  renderTable();
  renderProxy();
  renderPlaybook();
  renderOperations();
}

function renderLocalData() {
  renderScores();
  renderTraffic();
  renderAttacks();
  renderSystem();
  renderTable();
  renderProxy();
  renderPlaybook();
  renderOperations();
}

function startMesh() {
  const canvas = $("#mesh");
  const ctx = canvas.getContext("2d");
  const dots = Array.from({ length: 34 }, () => ({ x: Math.random(), y: Math.random(), vx: (Math.random() - 0.5) * 0.00055, vy: (Math.random() - 0.5) * 0.00055 }));
  let visible = true;
  function size() {
    const ratio = Math.min(devicePixelRatio, 1.5);
    canvas.width = canvas.offsetWidth * ratio;
    canvas.height = canvas.offsetHeight * ratio;
  }
  function draw() {
    if (!visible) {
      requestAnimationFrame(draw);
      return;
    }
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const w = canvas.width;
    const h = canvas.height;
    const gradient = ctx.createRadialGradient(w * 0.55, h * 0.35, 40, w * 0.55, h * 0.35, Math.max(w, h));
    gradient.addColorStop(0, "rgba(74,116,167,0.48)");
    gradient.addColorStop(0.55, "rgba(20,42,68,0.52)");
    gradient.addColorStop(1, "rgba(8,20,38,1)");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, w, h);
    dots.forEach((dot, i) => {
      dot.x += dot.vx;
      dot.y += dot.vy;
      if (dot.x < 0 || dot.x > 1) dot.vx *= -1;
      if (dot.y < 0 || dot.y > 1) dot.vy *= -1;
      const x = dot.x * w;
      const y = dot.y * h;
      ctx.fillStyle = i % 9 === 0 ? palette.red : palette.cyan;
      ctx.globalAlpha = i % 9 === 0 ? 0.85 : 0.42;
      ctx.beginPath();
      ctx.arc(x, y, i % 9 === 0 ? 3.6 : 2.2, 0, Math.PI * 2);
      ctx.fill();
      dots.slice(i + 1).forEach((other) => {
        const ox = other.x * w;
        const oy = other.y * h;
        const distance = Math.hypot(x - ox, y - oy);
        if (distance < 140) {
          ctx.strokeStyle = palette.ice;
          ctx.globalAlpha = 0.1 * (1 - distance / 140);
          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.lineTo(ox, oy);
          ctx.stroke();
        }
      });
    });
    ctx.globalAlpha = 1;
    requestAnimationFrame(draw);
  }
  size();
  addEventListener("resize", size);
  const observer = new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
  });
  observer.observe(canvas);
  draw();
}

async function init() {
  forceTop();
  setInitialFields();
  updateClock();
  setInterval(updateClock, 1000);
  renderLocalData();
  bindEvents();
  addChat("TRATA has correlated the current anomaly chain. Ask for CVE priority, MITRE mapping, or recommended response.");
  for (let i = 0; i < 6; i += 1) addAuditEvent(true);
  requestAnimationFrame(() => {
    $("#loader").classList.add("hidden");
    forceTop();
    setTimeout(startMesh, 80);
  });
  hydrate();
  setInterval(addAuditEvent, 2300);
  setInterval(() => {
    const traffic = state.data.dashboard.traffic;
    traffic.push(Math.round(38 + Math.random() * 92));
    traffic.shift();
    renderTraffic();
  }, 3000);
}

init();
