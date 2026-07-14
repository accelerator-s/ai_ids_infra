// 内联 SVG 加载器：图标只拉取一次并缓存，返回 <span class="icon">，
// 内部 <svg> 使用 stroke="currentColor"，颜色随主题变化。

const cache = new Map();

async function rawSvg(name) {
  if (!cache.has(name)) {
    cache.set(
      name,
      fetch(`/resources/icons/${name}.svg`)
        .then((r) => (r.ok ? r.text() : ""))
        .catch(() => "")
    );
  }
  return cache.get(name);
}

export async function iconEl(name) {
  const span = document.createElement("span");
  span.className = "icon";
  span.innerHTML = await rawSvg(name);
  return span;
}

// 把 root 内所有 <span data-icon="name"> 替换成内联 SVG。
export async function hydrateIcons(root) {
  const targets = root.querySelectorAll("[data-icon]");
  await Promise.all(
    [...targets].map(async (el) => {
      el.classList.add("icon");
      el.innerHTML = await rawSvg(el.dataset.icon);
    })
  );
}

export const icons = { iconEl, hydrateIcons };
