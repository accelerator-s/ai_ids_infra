import { hydrateIcons } from "../../core/icons.js";
import { RISK_LEVELS, riskLevelName } from "../../core/api.js";
import { renderState } from "../state-card/state-card.js";

const RING_RADIUS = 48;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

// 与后端 /api/status 的 modules 字段一一对应。
const MODULES = [
  { name: "database", label: "数据库" },
  { name: "rule_engine", label: "规则检测" },
  { name: "risk_score", label: "风险评分" },
  { name: "behavior_detector", label: "行为检测" },
  { name: "packet_parser", label: "协议解析" },
  { name: "live_capture", label: "实时抓包" },
  { name: "pcap_analyzer", label: "离线分析" },
  { name: "ai_analyzer", label: "AI 研判" },
  { name: "ai_report", label: "AI 报告" },
];

const CORE_MODULES = ["database", "rule_engine"];

export async function mount(root, ctx) {
  await hydrateIcons(root);

  const ring = root.querySelector("[data-readiness-ring]");
  const ringValue = root.querySelector("[data-readiness-value]");
  const modulesHost = root.querySelector("[data-modules]");
  const diagnostic = root.querySelector("[data-diagnostic]");
  const statCards = root.querySelector("[data-stat-cards]");
  const attackChart = root.querySelector("[data-attack-chart]");
  const riskChart = root.querySelector("[data-risk-chart]");
  const ipChart = root.querySelector("[data-ip-chart]");
  const recentHost = root.querySelector("[data-recent-alerts]");
  const gotoAlerts = root.querySelector("[data-goto-alerts]");

  ring.style.strokeDasharray = `${RING_CIRCUMFERENCE}`;
  ring.style.strokeDashoffset = `${RING_CIRCUMFERENCE}`;

  gotoAlerts.addEventListener("click", () => ctx.bus.emit("route", "alerts"));

  let lastHealth;
  ctx.bus.on("health", (data) => {
    lastHealth = data;
    renderHealth(data);
  });

  let statsLoading = false;
  ctx.bus.on("route", (id) => {
    if (id === "overview") loadStats();
  });
  loadStats();

  function renderHealth(data) {
    const reachable = data != null;
    const modules = data?.modules || {};
    const readyCount = MODULES.filter((m) => modules[m.name]?.ready).length;
    const readiness = reachable ? readyCount / MODULES.length : 0;
    const coreReady = CORE_MODULES.every((name) => modules[name]?.ready);
    const state = !reachable || !coreReady ? "bad" : readyCount < MODULES.length ? "warn" : "ok";

    ring.dataset.state = state;
    ring.style.strokeDashoffset = `${RING_CIRCUMFERENCE * (1 - readiness)}`;
    ringValue.textContent = `${Math.round(readiness * 100)}%`;

    modulesHost.innerHTML = "";
    for (const meta of MODULES) {
      const info = modules[meta.name];
      const ready = Boolean(reachable && info?.ready);
      const item = document.createElement("div");
      item.className = "overview__module";
      item.dataset.state = !reachable ? "off" : ready ? "ok" : "pending";
      if (!ready && info?.reason) item.title = info.reason;

      const dot = document.createElement("span");
      dot.className = "overview__module-dot";
      const label = document.createElement("strong");
      label.textContent = meta.label;
      const stateText = document.createElement("span");
      stateText.textContent = !reachable ? "未知" : ready ? "就绪" : "待实现";
      item.append(dot, label, stateText);
      modulesHost.append(item);
    }

    diagnostic.dataset.state = state;
    diagnostic.textContent = diagnosticText({ reachable, modules, coreReady, readyCount });
  }

  function diagnosticText({ reachable, modules, coreReady, readyCount }) {
    if (!reachable) {
      return "后端健康检查没有返回结果。请确认服务进程、端口和浏览器访问地址是否一致。";
    }
    if (!coreReady) {
      const broken = CORE_MODULES.filter((name) => !modules[name]?.ready)
        .map((name) => modules[name]?.reason || `${name} 不可用`)
        .join("；");
      return `核心链路异常：${broken}`;
    }
    if (readyCount < MODULES.length) {
      const pending = MODULES.filter((m) => !modules[m.name]?.ready).map((m) => m.label);
      return `数据库与规则库已就绪，可查看告警和统计。待实现模块：${pending.join("、")}，对应页面会展示开发进度提示。`;
    }
    return "全部模块就绪，检测链路完整可用。";
  }

  async function loadStats() {
    if (statsLoading) return;
    statsLoading = true;
    try {
      const stats = await ctx.api.stats();
      renderStatCards(stats);
      renderAttackChart(stats.attack_type_distribution || {});
      renderRiskChart(stats.risk_level_distribution || {});
      renderIpChart(stats.top_source_ips || []);
      renderRecentAlerts(stats.recent_alerts || []);
    } catch (err) {
      const opts = { kind: "error", title: "统计数据加载失败", detail: err.message, retry: loadStats };
      statCards.innerHTML = "";
      await renderState(attackChart, opts);
      await renderState(riskChart, { ...opts, retry: undefined });
      await renderState(ipChart, { ...opts, retry: undefined });
      await renderState(recentHost, { ...opts, retry: undefined });
    } finally {
      statsLoading = false;
    }
  }

  function renderStatCards(stats) {
    const riskDist = stats.risk_level_distribution || {};
    const severe = (riskDist.critical || 0) + (riskDist.high || 0);
    const ruleCount = lastHealth?.modules?.rule_engine?.rule_count;

    const cards = [
      { icon: "siren", label: "告警总数", value: stats.total_alerts ?? 0 },
      { icon: "table", label: "分析任务", value: stats.total_tasks ?? 0 },
      { icon: "alert", label: "高危及以上告警", value: severe, tone: severe > 0 ? "danger" : "" },
      { icon: "doc", label: "已加载规则", value: ruleCount ?? "—" },
    ];

    statCards.innerHTML = "";
    for (const card of cards) {
      const el = document.createElement("article");
      el.className = "overview__stat card";
      if (card.tone) el.dataset.tone = card.tone;
      el.innerHTML = `
        <span class="icon" data-icon="${card.icon}"></span>
        <div>
          <strong>${card.value}</strong>
          <span>${card.label}</span>
        </div>`;
      statCards.append(el);
    }
    hydrateIcons(statCards);
  }

  function renderBars(host, rows, { emptyTitle, emptyDetail }) {
    host.innerHTML = "";
    if (!rows.length) {
      renderState(host, { kind: "empty", title: emptyTitle, detail: emptyDetail });
      return;
    }
    const max = Math.max(...rows.map((row) => row.count), 1);
    const list = document.createElement("div");
    list.className = "overview__bars";
    for (const row of rows) {
      const item = document.createElement("div");
      item.className = "overview__bar-row";
      item.innerHTML = `
        <span class="overview__bar-label" title="${row.label}">${row.label}</span>
        <span class="overview__bar-track"><span style="width:${Math.max((row.count / max) * 100, 4)}%"></span></span>
        <span class="overview__bar-count">${row.count}</span>`;
      list.append(item);
    }
    host.append(list);
  }

  function renderAttackChart(dist) {
    const rows = Object.entries(dist)
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count);
    renderBars(attackChart, rows, {
      emptyTitle: "暂无攻击类型数据",
      emptyDetail: "检测链路产生告警后，这里会按攻击类型汇总。",
    });
  }

  function renderRiskChart(dist) {
    riskChart.innerHTML = "";
    const total = Object.values(dist).reduce((sum, n) => sum + n, 0);
    if (!total) {
      renderState(riskChart, {
        kind: "empty",
        title: "暂无风险等级数据",
        detail: "告警产生后，这里会展示各风险等级的占比。",
      });
      return;
    }
    const list = document.createElement("div");
    list.className = "overview__levels";
    for (const level of RISK_LEVELS) {
      const count = dist[level] || 0;
      if (!count) continue;
      const row = document.createElement("div");
      row.className = "overview__level-row";
      row.innerHTML = `
        <span class="badge badge--${level}">${riskLevelName(level)}</span>
        <span class="overview__bar-track"><span class="is-${level}" style="width:${Math.max((count / total) * 100, 4)}%"></span></span>
        <span class="overview__bar-count">${count}</span>`;
      list.append(row);
    }
    riskChart.append(list);
  }

  function renderIpChart(items) {
    const rows = items.map((item) => ({ label: item.src_ip, count: item.count }));
    renderBars(ipChart, rows, {
      emptyTitle: "暂无来源 IP 数据",
      emptyDetail: "告警产生后，这里会列出触发次数最多的来源 IP。",
    });
  }

  function renderRecentAlerts(alerts) {
    recentHost.innerHTML = "";
    if (!alerts.length) {
      renderState(recentHost, {
        kind: "empty",
        title: "暂无告警记录",
        detail: "抓包或离线分析模块产生告警后会显示在这里。",
      });
      return;
    }

    const table = document.createElement("table");
    table.className = "overview__table";
    table.innerHTML = `
      <thead>
        <tr>
          <th>时间</th><th>源 IP</th><th>方法</th><th>路径</th>
          <th>攻击类型</th><th>风险等级</th><th>分数</th>
        </tr>
      </thead>`;
    const tbody = document.createElement("tbody");
    for (const alert of alerts) {
      const tr = document.createElement("tr");
      const cells = [
        formatTime(alert.created_at),
        alert.src_ip || "—",
        alert.method || "—",
        alert.path || "—",
        alert.attack_type || "—",
      ];
      for (const value of cells) {
        const td = document.createElement("td");
        td.textContent = value;
        td.title = value;
        tr.append(td);
      }
      const levelTd = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `badge badge--${alert.risk_level}`;
      badge.textContent = riskLevelName(alert.risk_level);
      levelTd.append(badge);
      tr.append(levelTd);
      const scoreTd = document.createElement("td");
      scoreTd.textContent = Number(alert.score ?? 0).toFixed(1);
      tr.append(scoreTd);
      tbody.append(tr);
    }
    table.append(tbody);
    recentHost.append(table);
  }
}

function formatTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").slice(0, 19);
}
