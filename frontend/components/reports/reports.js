import { hydrateIcons } from "../../core/icons.js";
import { renderState } from "../state-card/state-card.js";

export async function mount(root, ctx) {
  await hydrateIcons(root);

  const gate = root.querySelector("[data-gate]");
  const ui = root.querySelector("[data-ui]");
  const generateForm = root.querySelector("[data-generate]");
  const taskSelect = root.querySelector("[data-task-select]");
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
    taskSelect.innerHTML = "";
    try {
      const data = await ctx.api.tasks({ limit: 100 });
      const items = data.items || [];
      if (!items.length) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "（暂无分析任务）";
        taskSelect.append(opt);
        generateBtn.disabled = true;
        return;
      }
      generateBtn.disabled = false;
      for (const task of items) {
        const opt = document.createElement("option");
        opt.value = task.id;
        opt.textContent = `#${task.id} · ${task.task_type} · ${task.target || "无目标"} · ${task.status}`;
        taskSelect.append(opt);
      }
    } catch {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "（任务列表加载失败）";
      taskSelect.append(opt);
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
      const item = document.createElement("article");
      item.className = "reports__item";
      item.innerHTML = `
        <strong>报告 #${report.id}</strong>
        <span>任务 #${report.task_id ?? "—"} · ${formatTime(report.created_at)}</span>
        <p>${report.summary || ""}</p>`;
      list.append(item);
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
      const data = await ctx.api.reports();
      renderReports(data.items || []);
    } catch (err) {
      showMsg(err.message, false);
    } finally {
      busy.hidden = true;
      generateBtn.disabled = false;
    }
  });

  ctx.bus.on("route", (id) => {
    if (id === "reports" && !moduleReady) checkModule();
  });
  checkModule();
}

function formatTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").slice(0, 19);
}
