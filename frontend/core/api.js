// 后端 JSON API 的轻量封装，只负责传输和错误归一化。
// 路由定义见仓库根目录 API.md；未实现的模块后端会返回 501，
// 这里把结构化错误透传给页面，由页面渲染主题化的待实现提示。

export const RISK_LEVELS = ["critical", "high", "medium", "low", "normal"];

export const RISK_LEVEL_NAMES = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  normal: "正常",
};

export function riskLevelName(level) {
  return RISK_LEVEL_NAMES[level] ?? String(level ?? "");
}

async function request(method, path, body) {
  const opts = { method, headers: {} };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const detail = data && data.detail;
    const message =
      (detail && typeof detail === "object" && detail.message) ||
      (typeof detail === "string" && detail) ||
      `请求失败 (${res.status})`;
    const error = new Error(message);
    error.status = res.status;
    if (detail && typeof detail === "object") {
      error.code = detail.code || "";
      error.module = detail.module || "";
    }
    throw error;
  }
  return data;
}

function withQuery(path, params = {}) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, value);
    }
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

export const api = {
  status: () => request("GET", "/api/status"),

  config: () => request("GET", "/api/config"),
  saveConfig: (payload) => request("POST", "/api/config", payload),
  llmModels: (base_url, api_key) => request("POST", "/api/llm/models", { base_url, api_key }),
  llmTest: (payload) => request("POST", "/api/llm/test", payload),

  captureInterfaces: () => request("GET", "/api/capture/interfaces"),
  captureStart: (payload) => request("POST", "/api/capture/start", payload),
  captureStop: (task_id) => request("POST", "/api/capture/stop", { task_id }),

  pcapAnalyze: (formData) => request("POST", "/api/pcap/analyze", formData),

  tasks: (params) => request("GET", withQuery("/api/tasks", params)),
  alerts: (params) => request("GET", withQuery("/api/alerts", params)),
  alert: (id) => request("GET", `/api/alerts/${id}`),
  stats: () => request("GET", "/api/stats"),

  reports: () => request("GET", "/api/reports"),
  report: (id) => request("GET", `/api/reports/${id}`),
  generateReport: (task_id) => request("POST", "/api/reports/generate", { task_id }),
};
