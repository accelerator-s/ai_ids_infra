import { hydrateIcons, iconEl } from "../../core/icons.js";

const TABS = [
  { id: "overview", label: "总览", icon: "status" },
  { id: "capture", label: "实时抓包", icon: "radar" },
  { id: "pcap", label: "离线分析", icon: "file" },
  { id: "alerts", label: "告警中心", icon: "siren" },
  { id: "reports", label: "AI 报告", icon: "robot" },
  { id: "config", label: "系统配置", icon: "wrench" },
];

export async function mount(root, ctx) {
  await hydrateIcons(root);
  const nav = root.querySelector("[data-tabs]");

  const buttons = new Map();
  for (const tab of TABS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "rail__tab";
    btn.dataset.tab = tab.id;
    btn.title = tab.label;
    btn.setAttribute("aria-label", tab.label);
    const ic = await iconEl(tab.icon);
    ic.classList.add("rail__tab-icon");
    btn.append(ic);
    const span = document.createElement("span");
    span.textContent = tab.label;
    btn.append(span);
    btn.addEventListener("click", () => ctx.bus.emit("route", tab.id));
    nav.append(btn);
    buttons.set(tab.id, btn);
  }

  ctx.bus.on("route", (id) => {
    for (const [tabId, btn] of buttons) {
      btn.classList.toggle("is-active", tabId === id);
    }
  });
}
