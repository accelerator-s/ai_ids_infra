import { hydrateIcons } from "../../core/icons.js";
import { renderState } from "../state-card/state-card.js";

export async function mount(root, ctx) {
  await hydrateIcons(root);

  const gate = root.querySelector("[data-gate]");
  const form = root.querySelector("[data-form]");
  const ifaceSelect = root.querySelector("[data-iface]");
  const targetType = root.querySelector("[data-target-type]");
  const target = root.querySelector("[data-target]");
  const port = root.querySelector("[data-port]");
  const startBtn = root.querySelector("[data-start]");
  const stopBtn = root.querySelector("[data-stop]");
  const busy = root.querySelector("[data-busy]");
  const msg = root.querySelector("[data-msg]");
  const taskBox = root.querySelector("[data-task]");

  let checking = false;
  let moduleReady = false;
  let runningTaskId = null;

  function showMsg(text, ok) {
    msg.hidden = !text;
    msg.textContent = text || "";
    msg.className = `capture__msg ${text ? (ok ? "is-ok" : "is-err") : ""}`;
  }

  // 直接请求网卡列表来探测模块状态：模块未实现时后端返回 501。
  async function checkModule() {
    if (checking) return;
    checking = true;
    form.hidden = true;
    await renderState(gate, { kind: "loading", title: "正在检测实时抓包模块" });
    try {
      const data = await ctx.api.captureInterfaces();
      moduleReady = true;
      gate.innerHTML = "";
      form.hidden = false;
      fillInterfaces(data.interfaces || []);
    } catch (err) {
      moduleReady = false;
      await renderState(gate, {
        kind: err.status === 501 ? "pending" : "error",
        title: err.status === 501 ? "实时抓包模块开发中" : "模块状态检测失败",
        detail: err.message,
        retry: checkModule,
        retryLabel: "重新检测",
      });
    } finally {
      checking = false;
    }
  }

  function fillInterfaces(interfaces) {
    ifaceSelect.innerHTML = "";
    if (!interfaces.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "（没有可用网卡）";
      ifaceSelect.append(opt);
      return;
    }
    for (const item of interfaces) {
      const name = typeof item === "string" ? item : item.name;
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = typeof item === "object" && item.description ? `${name} · ${item.description}` : name;
      ifaceSelect.append(opt);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showMsg("", true);
    if (!target.value.trim()) {
      showMsg("请先填写目标 IP 或域名", false);
      return;
    }
    busy.hidden = false;
    startBtn.disabled = true;
    try {
      const task = await ctx.api.captureStart({
        interface: ifaceSelect.value,
        target_type: targetType.value,
        target: target.value.trim(),
        port: Number(port.value) || 80,
      });
      runningTaskId = task.id;
      stopBtn.disabled = false;
      taskBox.hidden = false;
      taskBox.textContent = `抓包任务 #${task.id} 已启动，目标 ${task.target}，状态：${task.status}`;
      showMsg("抓包已启动", true);
    } catch (err) {
      showMsg(err.message, false);
    } finally {
      busy.hidden = true;
      startBtn.disabled = false;
    }
  });

  stopBtn.addEventListener("click", async () => {
    if (runningTaskId == null) return;
    showMsg("", true);
    stopBtn.disabled = true;
    try {
      await ctx.api.captureStop(runningTaskId);
      taskBox.textContent = `抓包任务 #${runningTaskId} 已停止`;
      runningTaskId = null;
      showMsg("抓包已停止", true);
    } catch (err) {
      showMsg(err.message, false);
      stopBtn.disabled = false;
    }
  });

  ctx.bus.on("route", (id) => {
    if (id === "capture" && !moduleReady) checkModule();
  });
  checkModule();
}
