import { iconEl } from "../../core/icons.js";

const KINDS = {
  empty: { icon: "doc", cls: "state-card--empty" },
  loading: { icon: "spark", cls: "state-card--loading" },
  error: { icon: "alert", cls: "state-card--error" },
  pending: { icon: "wrench", cls: "state-card--pending" },
};

// 向 host 渲染主题化的空态 / 加载 / 错误 / 待实现占位，
// 让缺数据和模块未完成的页面看起来是有意为之的状态。
export async function renderState(host, { kind = "empty", title = "", detail = "", retry, retryLabel = "重试" } = {}) {
  const spec = KINDS[kind] || KINDS.empty;
  host.innerHTML = "";

  const card = document.createElement("div");
  card.className = `state-card ${spec.cls}`;

  const icon = await iconEl(spec.icon);
  icon.classList.add("state-card__icon");
  card.append(icon);

  if (kind === "loading") {
    const bar = document.createElement("div");
    bar.className = "state-card__shimmer";
    card.append(bar);
  }

  if (kind === "pending") {
    const tag = document.createElement("span");
    tag.className = "state-card__tag";
    tag.textContent = "模块待实现";
    card.append(tag);
  }

  if (title) {
    const h = document.createElement("p");
    h.className = "state-card__title";
    h.textContent = title;
    card.append(h);
  }

  if (detail) {
    const d = document.createElement("p");
    d.className = "state-card__detail";
    d.textContent = detail;
    card.append(d);
  }

  if (typeof retry === "function") {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn state-card__retry";
    btn.textContent = retryLabel;
    btn.addEventListener("click", retry);
    card.append(btn);
  }

  host.append(card);
  return card;
}
