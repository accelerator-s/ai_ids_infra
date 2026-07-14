import { hydrateIcons } from "../../core/icons.js";
import { onHealth, moduleReady, moduleReason } from "../../core/health.js";
import { renderState } from "../state-card/state-card.js";

const TASK_STATUS_NAMES = {
  pending: "等待中",
  running: "进行中",
  finished: "已完成",
  failed: "失败",
  stopped: "已停止",
};

export async function mount(root, ctx) {
  await hydrateIcons(root);

  const gate = root.querySelector("[data-gate]");
  const form = root.querySelector("[data-form]");
  const drop = root.querySelector("[data-drop]");
  const fileInput = root.querySelector("[data-file]");
  const dropTitle = root.querySelector("[data-drop-title]");
  const dropSub = root.querySelector("[data-drop-sub]");
  const analyzeBtn = root.querySelector("[data-analyze]");
  const busy = root.querySelector("[data-busy]");
  const msg = root.querySelector("[data-msg]");
  const tasksHost = root.querySelector("[data-tasks]");

  let selectedFile = null;

  function showMsg(text, ok) {
    msg.hidden = !text;
    msg.textContent = text || "";
    msg.className = `pcap__msg ${text ? (ok ? "is-ok" : "is-err") : ""}`;
  }

  // 分析入口是 POST，不适合在挂载时试探，改用 /api/status 汇报的模块状态做门禁。
  onHealth(async (data) => {
    if (data === null) {
      form.hidden = true;
      await renderState(gate, {
        kind: "error",
        title: "服务不可达",
        detail: "后端健康检查没有返回结果，请确认服务进程和访问地址。",
      });
      return;
    }
    if (moduleReady("pcap_analyzer")) {
      gate.innerHTML = "";
      form.hidden = false;
      return;
    }
    form.hidden = true;
    await renderState(gate, {
      kind: "pending",
      title: "pcap 离线分析模块开发中",
      detail: moduleReason("pcap_analyzer") || "模块尚未实现，实现落地后此页面会自动启用。",
    });
  });

  function setFile(file) {
    selectedFile = file || null;
    analyzeBtn.disabled = !selectedFile;
    if (selectedFile) {
      dropTitle.textContent = selectedFile.name;
      dropSub.textContent = `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB`;
    } else {
      dropTitle.textContent = "点击选择或拖入 pcap 文件";
      dropSub.textContent = "支持 .pcap / .pcapng";
    }
  }

  fileInput.addEventListener("change", () => setFile(fileInput.files[0]));
  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("is-over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("is-over"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("is-over");
    if (event.dataTransfer.files.length) setFile(event.dataTransfer.files[0]);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedFile) return;
    showMsg("", true);
    busy.hidden = false;
    analyzeBtn.disabled = true;
    try {
      const fd = new FormData();
      fd.append("file", selectedFile);
      const result = await ctx.api.pcapAnalyze(fd);
      showMsg(`分析任务 #${result.task_id ?? result.id ?? ""} 已创建`, true);
      setFile(null);
      loadTasks();
    } catch (err) {
      showMsg(err.message, false);
    } finally {
      busy.hidden = true;
      analyzeBtn.disabled = !selectedFile;
    }
  });

  async function loadTasks() {
    try {
      const data = await ctx.api.tasks({ limit: 20 });
      renderTasks(data.items || []);
    } catch (err) {
      await renderState(tasksHost, {
        kind: "error",
        title: "任务列表加载失败",
        detail: err.message,
        retry: loadTasks,
      });
    }
  }

  function renderTasks(items) {
    tasksHost.innerHTML = "";
    if (!items.length) {
      renderState(tasksHost, {
        kind: "empty",
        title: "暂无分析任务",
        detail: "抓包或离线分析模块创建任务后会显示在这里。",
      });
      return;
    }
    const table = document.createElement("table");
    table.className = "pcap__table";
    table.innerHTML = `
      <thead>
        <tr><th>ID</th><th>类型</th><th>目标</th><th>状态</th><th>HTTP 请求</th><th>告警</th><th>创建时间</th></tr>
      </thead>`;
    const tbody = document.createElement("tbody");
    for (const task of items) {
      const tr = document.createElement("tr");
      const cells = [
        `#${task.id}`,
        task.task_type === "pcap" ? "离线分析" : task.task_type === "capture" ? "实时抓包" : task.task_type,
        task.target || "—",
        TASK_STATUS_NAMES[task.status] || task.status,
        String(task.http_count ?? 0),
        String(task.alert_count ?? 0),
        formatTime(task.created_at),
      ];
      for (const value of cells) {
        const td = document.createElement("td");
        td.textContent = value;
        td.title = value;
        tr.append(td);
      }
      tbody.append(tr);
    }
    table.append(tbody);
    tasksHost.append(table);
  }

  ctx.bus.on("route", (id) => {
    if (id === "pcap") loadTasks();
  });
  loadTasks();
}

function formatTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").slice(0, 19);
}
