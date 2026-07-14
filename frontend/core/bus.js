// 极简发布订阅，让组件之间保持解耦：
// rail 发出 "route"，app 轮询发出 "health"，配置页发出 "config-saved"。

export function createBus() {
  const map = new Map();
  return {
    on(event, fn) {
      if (!map.has(event)) map.set(event, new Set());
      map.get(event).add(fn);
      return () => map.get(event)?.delete(fn);
    },
    emit(event, payload) {
      map.get(event)?.forEach((fn) => fn(payload));
    },
  };
}
