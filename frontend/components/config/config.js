import { hydrateIcons } from "../../core/icons.js";
import { createSelect } from "./select.js";

export async function mount(root, ctx) {
  await hydrateIcons(root);

  const port = root.querySelector("[data-port]");
  const portHint = root.querySelector("[data-port-hint]");
  const base = root.querySelector("[data-base]");
  const key = root.querySelector("[data-key]");
  const modelSelect = createSelect(root.querySelector("[data-model-select]"));
  const temp = root.querySelector("[data-temp]");
  const tempVal = root.querySelector("[data-temp-val]");
  const fetchBtn = root.querySelector("[data-fetch-models]");
  const testBtn = root.querySelector("[data-test]");
  const saveBtn = root.querySelector("[data-save]");
  const busy = root.querySelector("[data-busy]");
  const msg = root.querySelector("[data-msg]");
  const testOut = root.querySelector("[data-test-out]");

  let savedHasApiKey = false;
  let savedBaseUrl = "";

  function showMsg(text, ok) {
    msg.hidden = !text;
    msg.textContent = text || "";
    msg.className = `config__msg ${text ? (ok ? "is-ok" : "is-err") : ""}`;
  }

  function setBusy(active) {
    busy.hidden = !active;
    fetchBtn.disabled = active;
    testBtn.disabled = active;
    saveBtn.disabled = active;
  }

  function updatePortHint() {
    const pagePort = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
    const configured = port.value.trim();
    if (configured && configured !== pagePort) {
      portHint.textContent = `当前页面通过端口 ${pagePort} 访问，新端口 ${configured} 重启服务后生效。`;
    } else {
      portHint.textContent = "修改端口后需重启服务进程生效。";
    }
  }

  // 密钥留空时，只要服务地址与已保存配置一致，后端会回落到已保存的密钥。
  function hasCredentials() {
    const baseUrl = base.value.trim();
    if (!baseUrl) return false;
    if (key.value.trim()) return true;
    return savedHasApiKey && baseUrl.replace(/\/+$/, "") === savedBaseUrl;
  }

  temp.addEventListener("input", () => {
    tempVal.textContent = Number(temp.value).toFixed(1);
  });
  port.addEventListener("input", updatePortHint);

  async function loadConfig() {
    try {
      const cfg = await ctx.api.config();
      port.value = cfg.server?.port ?? "";
      base.value = cfg.llm?.base_url || "";
      savedBaseUrl = base.value;
      savedHasApiKey = Boolean(cfg.llm?.has_api_key);
      modelSelect.setOptions([], cfg.llm?.model || "");
      temp.value = cfg.llm?.temperature ?? 0.2;
      tempVal.textContent = Number(temp.value).toFixed(1);
      updatePortHint();
    } catch (err) {
      showMsg(`读取配置失败：${err.message}`, false);
    }
  }
  await loadConfig();

  fetchBtn.addEventListener("click", async () => {
    showMsg("", true);
    if (!hasCredentials()) {
      showMsg("请先填写服务地址和访问密钥", false);
      return;
    }
    setBusy(true);
    try {
      const data = await ctx.api.llmModels(base.value.trim(), key.value.trim());
      const models = data.models || [];
      modelSelect.setOptions(models, modelSelect.value);
      showMsg(models.length ? `获取到 ${models.length} 个模型` : "服务没有返回可用模型", models.length > 0);
    } catch (err) {
      showMsg(err.message, false);
    } finally {
      setBusy(false);
    }
  });

  testBtn.addEventListener("click", async () => {
    showMsg("", true);
    testOut.hidden = true;
    testOut.textContent = "";
    if (!hasCredentials()) {
      showMsg("请先填写服务地址和访问密钥", false);
      return;
    }
    if (!modelSelect.value) {
      showMsg("请先选择模型", false);
      return;
    }
    setBusy(true);
    try {
      const result = await ctx.api.llmTest({
        base_url: base.value.trim(),
        api_key: key.value.trim(),
        model: modelSelect.value,
        temperature: Number(temp.value),
      });
      testOut.hidden = false;
      testOut.textContent = result.message;
      showMsg(`通讯成功（${Math.round(result.elapsed_ms)}ms）`, true);
    } catch (err) {
      showMsg(err.message, false);
    } finally {
      setBusy(false);
    }
  });

  saveBtn.addEventListener("click", async () => {
    showMsg("", true);
    setBusy(true);
    const payload = {
      server: {},
      llm: {
        base_url: base.value.trim(),
        model: modelSelect.value,
        temperature: Number(temp.value),
      },
    };
    if (port.value.trim()) payload.server.port = Number(port.value);
    if (key.value.trim()) payload.llm.api_key = key.value.trim();
    try {
      const cfg = await ctx.api.saveConfig(payload);
      savedBaseUrl = cfg.llm?.base_url || "";
      savedHasApiKey = Boolean(cfg.llm?.has_api_key);
      key.value = "";
      showMsg("已保存", true);
      updatePortHint();
      ctx.bus.emit("config-saved", cfg);
    } catch (err) {
      showMsg(`保存失败：${err.message}`, false);
    } finally {
      setBusy(false);
    }
  });
}
