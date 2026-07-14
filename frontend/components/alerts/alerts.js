import { hydrateIcons, iconEl } from "../../core/icons.js";
import { RISK_LEVELS, riskLevelName } from "../../core/api.js";
import { createSelect } from "../../core/select.js";
import { renderState } from "../state-card/state-card.js";

const PAGE_SIZE = 50;

export async function mount(root, ctx) {
  await hydrateIcons(root);

  const attackInput = root.querySelector("[data-filter-attack]");
  const levelSelect = createSelect(root.querySelector("[data-filter-level]"), {
    onChange: () => {
      offset = 0;
      load();
    },
  });
  levelSelect.setOptions([
    { value: "", label: "全部" },
    ...RISK_LEVELS.map((level) => ({ value: level, label: riskLevelName(level) })),
  ]);
  const ipInput = root.querySelector("[data-filter-ip]");
  const refreshBtn = root.querySelector("[data-refresh]");
  const tableHost = root.querySelector("[data-table]");
  const pager = root.querySelector("[data-pager]");
  const prevBtn = root.querySelector("[data-prev]");
  const nextBtn = root.querySelector("[data-next]");
  const pageLabel = root.querySelector("[data-page]");
  const detail = root.querySelector("[data-detail]");

  let offset = 0;
  let loading = false;
  let selectedId = null;

  async function load() {
    if (loading) return;
    loading = true;
    await renderState(tableHost, { kind: "loading", title: "正在加载告警" });
    try {
      const data = await ctx.api.alerts({
        attack_type: attackInput.value.trim(),
        risk_level: levelSelect.value,
        src_ip: ipInput.value.trim(),
        limit: PAGE_SIZE,
        offset,
      });
      renderTable(data.items || []);
    } catch (err) {
      pager.hidden = true;
      await renderState(tableHost, {
        kind: "error",
        title: "告警加载失败",
        detail: err.message,
        retry: load,
      });
    } finally {
      loading = false;
    }
  }

  function renderTable(items) {
    tableHost.innerHTML = "";
    if (!items.length) {
      pager.hidden = offset === 0;
      renderState(tableHost, {
        kind: "empty",
        title: offset === 0 ? "没有符合条件的告警" : "没有更多告警了",
        detail:
          offset === 0
            ? "调整筛选条件，或等待检测链路产生新的告警。"
            : "已到最后一页，可返回上一页。",
      });
      updatePager(items.length);
      return;
    }

    const table = document.createElement("table");
    table.className = "alerts__table";
    table.innerHTML = `
      <thead>
        <tr>
          <th>ID</th><th>时间</th><th>来源</th><th>方法</th><th>路径</th>
          <th>攻击类型</th><th>风险等级</th><th>分数</th>
        </tr>
      </thead>`;
    const tbody = document.createElement("tbody");
    for (const alert of items) {
      const tr = document.createElement("tr");
      tr.dataset.id = alert.id;
      if (alert.id === selectedId) tr.classList.add("is-selected");

      appendCell(tr, `#${alert.id}`);
      appendCell(tr, formatTime(alert.created_at));
      appendCell(tr, alert.src_ip || "—");
      appendCell(tr, alert.method || "—");
      appendCell(tr, alert.path || "—");
      appendCell(tr, alert.attack_type || "—");

      const levelTd = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `badge badge--${alert.risk_level}`;
      badge.textContent = riskLevelName(alert.risk_level);
      levelTd.append(badge);
      tr.append(levelTd);

      appendCell(tr, Number(alert.score ?? 0).toFixed(1));

      tr.addEventListener("click", () => {
        tbody.querySelectorAll("tr").forEach((row) => row.classList.remove("is-selected"));
        tr.classList.add("is-selected");
        selectedId = alert.id;
        showDetail(alert.id);
      });
      tbody.append(tr);
    }
    table.append(tbody);
    tableHost.append(table);
    updatePager(items.length);
  }

  function appendCell(tr, value) {
    const td = document.createElement("td");
    td.textContent = value;
    td.title = value;
    tr.append(td);
  }

  function updatePager(count) {
    pager.hidden = offset === 0 && count < PAGE_SIZE;
    prevBtn.disabled = offset === 0;
    nextBtn.disabled = count < PAGE_SIZE;
    pageLabel.textContent = `第 ${Math.floor(offset / PAGE_SIZE) + 1} 页`;
  }

  async function showDetail(id) {
    detail.innerHTML = "";
    await renderState(detail, { kind: "loading", title: "正在加载详情" });
    try {
      const alert = await ctx.api.alert(id);
      renderDetail(alert);
    } catch (err) {
      await renderState(detail, { kind: "error", title: "详情加载失败", detail: err.message });
    }
  }

  async function renderDetail(alert) {
    detail.innerHTML = "";

    const head = document.createElement("div");
    head.className = "alerts__detail-head";
    const icon = await iconEl("siren");
    icon.classList.add("icon");
    const title = document.createElement("h3");
    title.textContent = `告警 #${alert.id}`;
    const badge = document.createElement("span");
    badge.className = `badge badge--${alert.risk_level}`;
    badge.textContent = riskLevelName(alert.risk_level);
    head.append(icon, title, badge);
    detail.append(head);

    const facts = document.createElement("dl");
    facts.className = "alerts__facts";
    const rows = [
      ["时间", formatTime(alert.created_at)],
      ["攻击类型", alert.attack_type || "—"],
      ["风险分数", Number(alert.score ?? 0).toFixed(1)],
      ["来源", joinAddr(alert.src_ip, alert.src_port)],
      ["目标", joinAddr(alert.dst_ip, alert.dst_port)],
      ["请求", [alert.method, alert.path].filter(Boolean).join(" ") || "—"],
      ["查询串", alert.query || "—"],
      ["所属任务", alert.task_id != null ? `#${alert.task_id}` : "—"],
      ["AI 研判", alert.ai_judgement || "（未接入）"],
    ];
    for (const [label, value] of rows) {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value;
      facts.append(dt, dd);
    }
    detail.append(facts);

    const rules = Array.isArray(alert.matched_rules) ? alert.matched_rules : [];
    if (rules.length) {
      const rulesTitle = document.createElement("h4");
      rulesTitle.className = "alerts__section-title";
      rulesTitle.textContent = `命中规则（${rules.length}）`;
      detail.append(rulesTitle);
      const chips = document.createElement("div");
      chips.className = "alerts__chips";
      for (const rule of rules) {
        const chip = document.createElement("span");
        chip.className = "alerts__chip";
        chip.textContent = typeof rule === "string" ? rule : rule.name || rule.id || JSON.stringify(rule);
        chips.append(chip);
      }
      detail.append(chips);
    }

    const reason = alert.reason || alert.ai_reason;
    if (reason) {
      const reasonTitle = document.createElement("h4");
      reasonTitle.className = "alerts__section-title";
      reasonTitle.textContent = "判定说明";
      const text = document.createElement("p");
      text.className = "alerts__reason";
      text.textContent = reason;
      detail.append(reasonTitle, text);
    }
  }

  function joinAddr(ip, port) {
    if (!ip) return "—";
    return port != null ? `${ip}:${port}` : ip;
  }

  refreshBtn.addEventListener("click", () => {
    offset = 0;
    load();
  });
  for (const input of [attackInput, ipInput]) {
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        offset = 0;
        load();
      }
    });
  }
  prevBtn.addEventListener("click", () => {
    offset = Math.max(0, offset - PAGE_SIZE);
    load();
  });
  nextBtn.addEventListener("click", () => {
    offset += PAGE_SIZE;
    load();
  });

  ctx.bus.on("route", (id) => {
    if (id === "alerts") load();
  });
  load();
}

function formatTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").slice(0, 19);
}
