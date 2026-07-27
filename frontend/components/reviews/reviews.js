import { hydrateIcons, iconEl } from "../../core/icons.js";
import { riskLevelName } from "../../core/api.js";
import { createSelect } from "../../core/select.js";
import { renderState } from "../state-card/state-card.js";

const PAGE_SIZE = 30;

export async function mount(root, ctx) {
  await hydrateIcons(root);
  const listHost = root.querySelector("[data-list]");
  const detail = root.querySelector("[data-detail]");
  const count = root.querySelector("[data-count]");
  const pager = root.querySelector("[data-pager]");
  const pageLabel = root.querySelector("[data-page]");
  const prevBtn = root.querySelector("[data-prev]");
  const nextBtn = root.querySelector("[data-next]");
  const refreshBtn = root.querySelector("[data-refresh]");
  const statusSelect = createSelect(root.querySelector("[data-filter-status]"), {
    onChange: () => { offset = 0; selectedId = null; load(); },
  });
  statusSelect.setOptions([
    { value: "pending_review", label: "待处理" },
    { value: "completed", label: "已完成" },
    { value: "", label: "全部记录" },
  ], "pending_review");

  let offset = 0;
  let selectedId = null;
  let loading = false;

  async function load({ preserveSelection = false } = {}) {
    if (loading) return;
    loading = true;
    await renderState(listHost, { kind: "loading", title: "正在读取复核队列" });
    try {
      const data = await ctx.api.aiReviews({ status: statusSelect.value, limit: PAGE_SIZE, offset });
      const items = data.items || [];
      renderList(items);
      if (!preserveSelection || !items.some((item) => item.id === selectedId)) {
        selectedId = items[0]?.id ?? null;
      }
      markSelected();
      if (selectedId) await showDetail(selectedId);
      else await renderState(detail, {
        kind: "empty",
        title: statusSelect.value === "pending_review" ? "当前没有待复核记录" : "没有符合条件的记录",
        detail: statusSelect.value === "pending_review" ? "新的未完成研判请求会自动进入这里。" : "可切换复核状态查看其他记录。",
      });
    } catch (error) {
      count.textContent = "读取失败";
      pager.hidden = true;
      await renderState(listHost, { kind: "error", title: "复核队列加载失败", detail: error.message, retry: load });
    } finally {
      loading = false;
    }
  }

  function renderList(items) {
    listHost.innerHTML = "";
    count.textContent = items.length ? `本页 ${items.length} 条记录` : "本页无记录";
    for (const review of items) {
      const summary = review.request_summary || {};
      const button = document.createElement("button");
      button.type = "button";
      button.className = "reviews__item";
      button.dataset.id = review.id;
      button.innerHTML = `
        <span class="reviews__item-top">
          <span class="reviews__item-id">#${review.id}</span>
          <span class="reviews__status reviews__status--${review.status}">${statusName(review)}</span>
        </span>
        <strong>${escapeHtml(requestLine(summary))}</strong>
        <span class="reviews__item-meta">
          <span class="badge badge--${riskLevel(review.original_score)}">${riskLevelName(riskLevel(review.original_score))}</span>
          <span>${Number(review.original_score).toFixed(1)} 分</span>
          <span>${escapeHtml(summary.src_ip || "未记录来源")}</span>
        </span>`;
      button.addEventListener("click", async () => {
        selectedId = review.id;
        markSelected();
        await showDetail(review.id);
      });
      listHost.append(button);
    }
    pager.hidden = offset === 0 && items.length < PAGE_SIZE;
    prevBtn.disabled = offset === 0;
    nextBtn.disabled = items.length < PAGE_SIZE;
    pageLabel.textContent = `第 ${Math.floor(offset / PAGE_SIZE) + 1} 页`;
  }

  function markSelected() {
    listHost.querySelectorAll("[data-id]").forEach((node) => {
      node.classList.toggle("is-selected", Number(node.dataset.id) === selectedId);
    });
  }

  async function showDetail(id) {
    await renderState(detail, { kind: "loading", title: "正在读取请求详情" });
    try {
      renderDetail(await ctx.api.aiReview(id));
    } catch (error) {
      await renderState(detail, { kind: "error", title: "复核详情加载失败", detail: error.message, retry: () => showDetail(id) });
    }
  }

  async function renderDetail(review) {
    const summary = review.request_summary || {};
    const pending = review.status === "pending_review" && review.judgement === "manual_review";
    detail.innerHTML = "";

    const header = document.createElement("header");
    header.className = "reviews__case-head";
    const icon = await iconEl("doc");
    const heading = document.createElement("div");
    heading.innerHTML = `<span>复核单 #${review.id}</span><h3>${escapeHtml(requestLine(summary))}</h3>`;
    const state = document.createElement("span");
    state.className = `reviews__status reviews__status--${review.status}`;
    state.textContent = statusName(review);
    header.append(icon, heading, state);
    detail.append(header);

    const risk = document.createElement("div");
    risk.className = "reviews__risk";
    risk.innerHTML = `
      <div><span>原始风险</span><strong>${Number(review.original_score).toFixed(1)}</strong><small>/ 100</small></div>
      <span class="badge badge--${riskLevel(review.original_score)}">${riskLevelName(riskLevel(review.original_score))}</span>
      <p>${escapeHtml(review.reason || "无自动研判说明")}</p>`;
    detail.append(risk);

    detail.append(sectionTitle("请求上下文"));
    const facts = document.createElement("dl");
    facts.className = "reviews__facts";
    const factRows = [
      ["时间", formatTime(review.created_at)], ["来源", joinAddress(summary.src_ip, summary.src_port)],
      ["目标", joinAddress(summary.dst_ip, summary.dst_port)], ["方法", summary.method || "—"],
      ["路径", summary.path || "—"], ["所属任务", review.task_id == null ? "—" : `#${review.task_id}`],
    ];
    for (const [label, value] of factRows) {
      const dt = document.createElement("dt"); dt.textContent = label;
      const dd = document.createElement("dd"); dd.textContent = value;
      facts.append(dt, dd);
    }
    detail.append(facts);

    if (summary.query || summary.body) {
      const payload = document.createElement("div");
      payload.className = "reviews__payload";
      payload.textContent = summary.query || summary.body;
      detail.append(sectionTitle(summary.query ? "查询参数" : "请求体"), payload);
    }

    detail.append(sectionTitle(`命中规则（${(review.matched_rules || []).length}）`));
    const chips = document.createElement("div");
    chips.className = "reviews__chips";
    for (const rule of review.matched_rules || []) {
      const chip = document.createElement("span"); chip.textContent = String(rule); chips.append(chip);
    }
    if (!chips.children.length) chips.textContent = "未记录命中规则";
    detail.append(chips);

    if (pending) detail.append(buildDecisionForm(review));
    else detail.append(buildDecisionResult(review));
  }

  function buildDecisionForm(review) {
    const form = document.createElement("form");
    form.className = "reviews__decision";
    form.innerHTML = `
      <div class="reviews__decision-head"><div><h4>填写人工结论</h4><p>请基于请求上下文和命中规则进行判定。</p></div></div>
      <label class="field-label" for="review-attack-${review.id}">攻击类型</label>
      <input class="input" id="review-attack-${review.id}" name="attack_type" maxlength="64" value="${escapeHtml(review.attack_type === "Unknown" ? "" : review.attack_type)}" placeholder="判定恶意时必填" />
      <label class="field-label" for="review-reason-${review.id}">复核依据</label>
      <textarea class="textarea" id="review-reason-${review.id}" name="reason" minlength="2" maxlength="2000" required placeholder="说明判定依据，便于后续审计和追溯。"></textarea>
      <p class="reviews__form-error" data-form-error hidden></p>
      <div class="reviews__actions">
        <button class="btn reviews__benign" type="button" data-decision="benign"><span class="icon" data-icon="check"></span>确认为正常请求</button>
        <button class="btn reviews__malicious" type="button" data-decision="malicious"><span class="icon" data-icon="siren"></span>确认恶意并生成告警</button>
      </div>`;
    hydrateIcons(form);
    form.querySelectorAll("[data-decision]").forEach((button) => button.addEventListener("click", async () => {
      const judgement = button.dataset.decision;
      const reason = form.elements.reason.value.trim();
      const attackType = form.elements.attack_type.value.trim();
      const error = form.querySelector("[data-form-error]");
      error.hidden = true;
      if (reason.length < 2) { error.textContent = "请填写至少 2 个字的复核依据。"; error.hidden = false; return; }
      if (judgement === "malicious" && !attackType) { error.textContent = "判定为恶意时必须填写攻击类型。"; error.hidden = false; return; }
      const buttons = [...form.querySelectorAll("button")];
      buttons.forEach((item) => { item.disabled = true; });
      try {
        await ctx.api.decideAiReview(review.id, { judgement, attack_type: attackType, reason });
        selectedId = null;
        await load();
        ctx.bus.emit("reviews-changed");
      } catch (requestError) {
        error.textContent = requestError.message;
        error.hidden = false;
        buttons.forEach((item) => { item.disabled = false; });
      }
    }));
    return form;
  }

  function buildDecisionResult(review) {
    const box = document.createElement("div");
    box.className = `reviews__result reviews__result--${review.judgement}`;
    box.innerHTML = `<span>人工复核结论</span><strong>${review.judgement === "malicious" ? "确认恶意" : "确认正常"}</strong><p>${escapeHtml(review.reason || "")}</p>${review.alert_id ? `<a href="#" data-alert>查看关联告警 #${review.alert_id}</a>` : ""}`;
    box.querySelector("[data-alert]")?.addEventListener("click", (event) => { event.preventDefault(); ctx.bus.emit("route", "alerts"); });
    return box;
  }

  function sectionTitle(text) { const h = document.createElement("h4"); h.className = "reviews__section-title"; h.textContent = text; return h; }
  refreshBtn.addEventListener("click", () => { selectedId = null; load(); });
  prevBtn.addEventListener("click", () => { offset = Math.max(0, offset - PAGE_SIZE); selectedId = null; load(); });
  nextBtn.addEventListener("click", () => { offset += PAGE_SIZE; selectedId = null; load(); });
  ctx.bus.on("route", (route) => { if (route === "reviews") load({ preserveSelection: true }); });
}

function riskLevel(score) { if (score >= 90) return "critical"; if (score >= 70) return "high"; if (score >= 40) return "medium"; if (score >= 20) return "low"; return "normal"; }
function statusName(review) { if (review.status === "pending_review") return "待处理"; return review.judgement === "malicious" ? "已判定恶意" : "已判定正常"; }
function requestLine(summary) { return [summary.method, summary.path].filter(Boolean).join(" ") || "未记录请求路径"; }
function joinAddress(ip, port) { if (!ip) return "—"; return port == null ? String(ip) : `${ip}:${port}`; }
function formatTime(value) { if (!value) return "—"; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN", { hour12: false }); }
function escapeHtml(value) { const div = document.createElement("div"); div.textContent = String(value ?? ""); return div.innerHTML; }
