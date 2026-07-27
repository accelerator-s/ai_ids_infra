import { hydrateIcons, iconEl } from "../../core/icons.js";

const TABS = [
  { id: "overview", label: "总览", icon: "status" },
  { id: "capture", label: "实时抓包", icon: "radar" },
  { id: "pcap", label: "离线分析", icon: "file" },
  { id: "alerts", label: "告警中心", icon: "siren" },
  { id: "reviews", label: "人工复核", icon: "check" },
  { id: "reports", label: "AI 报告", icon: "robot" },
  { id: "config", label: "系统配置", icon: "wrench" },
];

export async function mount(root, ctx) {
  await hydrateIcons(root);
  const nav = root.querySelector("[data-tabs]");

  const buttons = new Map();

  async function addTab(tab) {
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
    span.className = "rail__tab-label";
    span.textContent = tab.label;
    btn.append(span);
    if (tab.id === "reviews") {
      const notice = document.createElement("span");
      notice.className = "rail__notice";
      notice.dataset.reviewNotice = "";
      notice.setAttribute("aria-label", "有待处理的人工复核");
      notice.hidden = true;
      btn.append(notice);
    }
    btn.addEventListener("click", () => ctx.bus.emit("route", tab.id));
    nav.append(btn);
    buttons.set(tab.id, btn);
  }

  for (const tab of TABS) await addTab(tab);

  async function syncReviewNotice() {
    const pending = await ctx.api.aiReviews({ status: "pending_review", limit: 1 });
    const notice = buttons.get("reviews").querySelector("[data-review-notice]");
    notice.hidden = (pending.items || []).length === 0;
  }

  await syncReviewNotice();
  ctx.bus.on("reviews-changed", syncReviewNotice);
  ctx.bus.on("health", syncReviewNotice);

  ctx.bus.on("route", (id) => {
    for (const [tabId, btn] of buttons) {
      btn.classList.toggle("is-active", tabId === id);
    }
  });
}
