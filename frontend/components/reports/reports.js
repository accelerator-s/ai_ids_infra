import { hydrateIcons } from "../../core/icons.js";
import { createSelect } from "../../core/select.js";
import { renderState } from "../state-card/state-card.js";

export async function mount(root, ctx) {
  await hydrateIcons(root);

  const gate = root.querySelector("[data-gate]");
  const ui = root.querySelector("[data-ui]");
  const generateForm = root.querySelector("[data-generate]");
  const taskSelect = createSelect(root.querySelector("[data-task-select]"), {
    emptyLabel: "（暂无分析任务）",
  });
  const generateBtn = root.querySelector("[data-generate-btn]");
  const busy = root.querySelector("[data-busy]");
  const msg = root.querySelector("[data-msg]");
  const list = root.querySelector("[data-list]");

  let checking = false;
  let moduleReady = false;

  function showMsg(text, ok) {
    msg.hidden = !text;
    msg.textContent = text || "";
    msg.className = `reports__msg ${text ? (ok ? "is-ok" : "is-err") : ""}`;
  }

  // 用报告列表接口探测模块状态：模块未实现时后端返回 501。
  async function checkModule() {
    if (checking) return;
    checking = true;
    ui.hidden = true;
    await renderState(gate, { kind: "loading", title: "正在检测 AI 报告模块" });
    try {
      const data = await ctx.api.reports();
      moduleReady = true;
      gate.innerHTML = "";
      ui.hidden = false;
      renderReports(data.items || []);
      loadTasks();
    } catch (err) {
      moduleReady = false;
      await renderState(gate, {
        kind: err.status === 501 ? "pending" : "error",
        title: err.status === 501 ? "AI 评测报告模块开发中" : "模块状态检测失败",
        detail: err.message,
        retry: checkModule,
        retryLabel: "重新检测",
      });
    } finally {
      checking = false;
    }
  }

  async function loadTasks() {
    try {
      const data = await ctx.api.tasks({ limit: 100 });
      const items = data.items || [];
      taskSelect.setOptions(
        items.map((task) => ({
          value: String(task.id),
          label: `#${task.id} · ${task.task_type} · ${task.target || "无目标"} · ${task.status}`,
        })),
      );
      generateBtn.disabled = !items.length;
    } catch {
      taskSelect.setOptions([], "", "（任务列表加载失败）");
      generateBtn.disabled = true;
    }
  }

  function renderReports(items) {
    list.innerHTML = "";
    if (!items.length) {
      renderState(list, {
        kind: "empty",
        title: "暂无历史报告",
        detail: "选择分析任务并生成报告后，会在这里列出。",
      });
      return;
    }
    for (const report of items) {
      list.append(renderReportItem(report));
    }
  }

  generateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!taskSelect.value) return;
    showMsg("", true);
    busy.hidden = false;
    generateBtn.disabled = true;
    try {
      await ctx.api.generateReport(Number(taskSelect.value));
      showMsg("报告生成完成", true);
    } catch (err) {
      showMsg(err.message, false);
    } finally {
      busy.hidden = true;
      generateBtn.disabled = false;
      try {
        const data = await ctx.api.reports();
        renderReports(data.items || []);
      } catch {}
    }
  });

  ctx.bus.on("route", (id) => {
    if (id === "reports" && !moduleReady) checkModule();
  });
  checkModule();
}

function renderReportItem(report) {
  const item = document.createElement("article");
  item.className = "reports__item";

  const title = document.createElement("strong");
  title.textContent = `报告 #${report.id}`;
  const meta = document.createElement("span");
  meta.textContent = [
    `任务 #${report.task_id ?? "—"}`,
    formatTime(report.created_at),
    report.model,
  ]
    .filter(Boolean)
    .join(" · ");
  item.append(title, meta);

  if (report.status === "failed") {
    item.classList.add("reports__item--failed");
    const error = document.createElement("p");
    error.className = "reports__error";
    error.textContent = `生成失败：${report.error_message || "未知原因"}`;
    item.append(error);
    return item;
  }

  const summary = document.createElement("p");
  summary.textContent = report.summary || "";
  item.append(summary);

  appendSection(item, "风险评估", report.risk_assessment);
  appendPoints(item, "主要发现", report.key_findings);
  appendPoints(item, "处置建议", report.recommendations);
  return item;
}

function appendSection(item, label, text) {
  if (!text) return;
  const head = document.createElement("h4");
  head.textContent = label;
  const body = document.createElement("p");
  body.textContent = text;
  item.append(head, body);
}

function appendPoints(item, label, entries) {
  if (!Array.isArray(entries) || !entries.length) return;
  const head = document.createElement("h4");
  head.textContent = label;
  const points = document.createElement("ul");
  points.className = "reports__points";
  for (const entry of entries) {
    const point = document.createElement("li");
    point.textContent = entry;
    points.append(point);
  }
  item.append(head, points);
}

function formatTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").slice(0, 19);
}
