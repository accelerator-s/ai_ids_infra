import { api } from "./core/api.js";
import { icons } from "./core/icons.js";
import { createBus } from "./core/bus.js";
import { initTheme } from "./core/theme.js";
import { initHealth } from "./core/health.js";

// 固定挂载的单例组件。
const SINGLETONS = [
  { name: "rail", host: "#rail" },
  { name: "topbar", host: "#topbar" },
];

// 每个页签一个组件，按路由显示或隐藏。
const PANES = ["overview", "capture", "pcap", "alerts", "reports", "config"];

const DEFAULT_ROUTE = "overview";
const HEALTH_INTERVAL = 15000;

async function loadComponent(name, host, ctx) {
  const html = await fetch(`/components/${name}/${name}.html`, { cache: "no-cache" }).then((r) => r.text());
  host.innerHTML = html;
  const mod = await import(`/components/${name}/${name}.js`);
  await mod.mount(host, ctx);
}

async function main() {
  initTheme();

  const bus = createBus();
  initHealth(bus);
  const ctx = { api, bus, icons };

  for (const { name, host } of SINGLETONS) {
    await loadComponent(name, document.querySelector(host), ctx);
  }

  const content = document.querySelector("#content");
  const panes = new Map();
  for (const name of PANES) {
    const host = document.createElement("div");
    host.className = "pane";
    host.dataset.pane = name;
    host.hidden = true;
    content.append(host);
    await loadComponent(name, host, ctx);
    panes.set(name, host);
  }

  bus.on("route", (id) => {
    if (!panes.has(id)) return;
    for (const [name, host] of panes) {
      const active = name === id;
      host.hidden = !active;
      host.classList.toggle("is-active", active);
      if (active) {
        host.classList.remove("is-active");
        void host.offsetWidth;
        host.classList.add("is-active");
      }
    }
  });

  bus.emit("route", DEFAULT_ROUTE);

  async function pollHealth() {
    try {
      const data = await api.status();
      bus.emit("health", data);
    } catch {
      bus.emit("health", null);
    }
  }
  pollHealth();
  setInterval(pollHealth, HEALTH_INTERVAL);
}

main();
