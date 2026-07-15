// 自定义下拉框：原生 select 无法自定义选项样式，这里用按钮加列表实现，
// 支持键盘上下选择和点击外部关闭。
export function createSelect(root) {
  const trigger = root.querySelector("[data-select-trigger]");
  const valueEl = root.querySelector("[data-select-value]");
  const list = root.querySelector("[data-select-list]");
  let options = [];
  let selected = "";
  let activeIndex = -1;

  function open() {
    if (!options.length) return;
    root.classList.add("is-open");
    list.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    activeIndex = Math.max(0, options.indexOf(selected));
    refreshActive();
  }

  function close() {
    root.classList.remove("is-open");
    list.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
  }

  function choose(value) {
    selected = value;
    valueEl.textContent = value || "（请选择模型）";
    list.querySelectorAll("[role=option]").forEach((item) => {
      item.setAttribute("aria-selected", String(item.dataset.value === selected));
    });
    close();
    trigger.focus();
  }

  function refreshActive() {
    list.querySelectorAll("[role=option]").forEach((item, index) => {
      item.classList.toggle("is-active", index === activeIndex);
    });
  }

  function move(delta) {
    if (!options.length) return;
    open();
    activeIndex = (activeIndex + delta + options.length) % options.length;
    refreshActive();
    list.children[activeIndex]?.scrollIntoView({ block: "nearest" });
  }

  function setOptions(next, preferred = "", emptyLabel = "（先获取模型列表）") {
    options = [...next];
    list.innerHTML = "";
    if (!options.length) {
      selected = preferred || "";
      valueEl.textContent = preferred || emptyLabel;
      close();
      return;
    }
    selected = options.includes(preferred) ? preferred : options[0];
    for (const value of options) {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "config-select__option";
      option.dataset.value = value;
      option.setAttribute("role", "option");
      option.setAttribute("aria-selected", String(value === selected));
      option.textContent = value;
      option.addEventListener("click", () => choose(value));
      list.append(option);
    }
    valueEl.textContent = selected;
  }

  trigger.addEventListener("click", () => {
    if (root.classList.contains("is-open")) close();
    else open();
  });
  trigger.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      move(event.key === "ArrowDown" ? 1 : -1);
    } else if (event.key === "Enter" && root.classList.contains("is-open")) {
      event.preventDefault();
      choose(options[activeIndex]);
    } else if (event.key === "Escape") {
      close();
    }
  });
  document.addEventListener("click", (event) => {
    if (!root.contains(event.target)) close();
  });

  return {
    get value() {
      return selected;
    },
    setOptions,
  };
}
