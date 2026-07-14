// 缓存最近一次 /api/status 的结果，页面据此判断模块是否就绪，
// 不用各自维护轮询。

let current = undefined;
const listeners = new Set();

export function initHealth(bus) {
  bus.on("health", (data) => {
    current = data;
    listeners.forEach((fn) => fn(data));
  });
}

export function getHealth() {
  return current;
}

export function moduleReady(name) {
  return Boolean(current && current.modules && current.modules[name]?.ready);
}

export function moduleReason(name) {
  return (current && current.modules && current.modules[name]?.reason) || "";
}

export function llmConfigured() {
  const llm = current?.llm;
  return Boolean(llm && llm.base_url && llm.model && llm.has_api_key);
}

export function onHealth(fn) {
  listeners.add(fn);
  if (current !== undefined) fn(current);
  return () => listeners.delete(fn);
}
