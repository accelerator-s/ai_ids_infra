import { iconEl } from "../../core/icons.js";
import { toggleTheme, currentTheme, onThemeChange } from "../../core/theme.js";

const TITLES = {
  overview: {
    title: "总览",
    sub: "查看模块就绪情况、告警统计和最近检测记录。",
    icon: "status",
  },
  capture: {
    title: "实时抓包",
    sub: "监听指定网卡，对目标 IP 或域名的 HTTP 明文流量做在线检测。",
    icon: "radar",
  },
  pcap: {
    title: "离线分析",
    sub: "上传 pcap 流量包，逐条解析 HTTP 请求并执行规则检测。",
    icon: "file",
  },
  alerts: {
    title: "告警中心",
    sub: "按攻击类型、风险等级和来源 IP 筛选告警，查看命中规则详情。",
    icon: "siren",
  },
  reports: {
    title: "AI 评测报告",
    sub: "对已完成的分析任务做汇总研判，输出风险概述和处置建议。",
    icon: "robot",
  },
  config: {
    title: "系统配置",
    sub: "设置服务端口和大模型接入参数，保存在服务端。",
    icon: "wrench",
  },
};

// 判定核心链路是否就绪：数据库和规则库必须可用，其余模块缺失只降级提示。
const CORE_MODULES = ["database", "rule_engine"];
const OPTIONAL_MODULES = [
  "behavior_detector",
  "packet_parser",
  "live_capture",
  "pcap_analyzer",
  "ai_analyzer",
  "ai_report",
];

export async function mount(root, ctx) {
  const titleEl = root.querySelector("[data-title]");
  const subEl = root.querySelector("[data-sub]");
  const pageIcon = root.querySelector("[data-page-icon]");
  const themeBtn = root.querySelector("[data-theme-toggle]");
  const health = root.querySelector("[data-health]");
  const healthText = root.querySelector("[data-health-text]");

  async function setPageIcon(name) {
    pageIcon.innerHTML = "";
    const ic = await iconEl(name);
    ic.classList.add("topbar__page-icon");
    pageIcon.append(ic);
  }
  async function setThemeIcon() {
    themeBtn.innerHTML = "";
    const ic = await iconEl(currentTheme() === "dark" ? "theme-sun" : "theme-moon");
    themeBtn.append(ic);
  }
  await setThemeIcon();
  await setPageIcon(TITLES.overview.icon);
  themeBtn.addEventListener("click", () => {
    toggleTheme();
  });
  onThemeChange(setThemeIcon);

  ctx.bus.on("route", async (id) => {
    const meta = TITLES[id] || TITLES.overview;
    titleEl.textContent = meta.title;
    subEl.textContent = meta.sub;
    await setPageIcon(meta.icon);
  });

  function setHealth(data) {
    const reachable = data != null;
    const modules = data?.modules || {};
    const coreReady = CORE_MODULES.every((name) => modules[name]?.ready);
    const pendingCount = OPTIONAL_MODULES.filter((name) => !modules[name]?.ready).length;

    const cls = !reachable ? "is-off" : !coreReady ? "is-bad" : pendingCount ? "is-pending" : "is-ok";
    health.classList.remove("is-ok", "is-bad", "is-pending", "is-off", "is-unknown");
    health.classList.add(cls);

    if (!reachable) {
      healthText.textContent = "服务不可达";
      health.title = "后端没有响应，请确认服务进程和访问地址";
    } else if (!coreReady) {
      healthText.textContent = "核心模块异常";
      health.title = "数据库或规则库不可用，详情见总览页";
    } else if (pendingCount) {
      healthText.textContent = `${pendingCount} 个模块待实现`;
      health.title = "核心链路可用，部分模块开发中，详情见总览页";
    } else {
      healthText.textContent = "服务正常";
      health.title = "全部模块就绪";
    }
  }
  ctx.bus.on("health", setHealth);
}
