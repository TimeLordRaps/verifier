(() => {
  "use strict";

  const links = [...document.querySelectorAll('a[data-orientation-preview="repository"]')];
  if (!links.length) return;

  const card = document.createElement("aside");
  card.id = "orientation-preview";
  card.className = "orientation-preview";
  card.hidden = true;
  card.setAttribute("role", "tooltip");
  document.body.append(card);

  let activeLink = null;
  let timer = null;

  const textElement = (tag, className, text) => {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = text;
    return element;
  };

  const position = (link) => {
    if (card.hidden) return;
    const rect = link.getBoundingClientRect();
    const margin = 12;
    const width = Math.min(420, window.innerWidth - margin * 2);
    card.style.width = `${width}px`;
    let left = Math.min(rect.left, window.innerWidth - width - margin);
    left = Math.max(margin, left);
    let top = rect.bottom + 10;
    if (top + card.offsetHeight > window.innerHeight - margin) {
      top = Math.max(margin, rect.top - card.offsetHeight - 10);
    }
    card.style.left = `${left}px`;
    card.style.top = `${top}px`;
  };

  const render = (link) => {
    card.replaceChildren();
    card.append(
      textElement(
        "span",
        "orientation-preview-eyebrow",
        "Repository definition · versioned with VSTD",
      ),
    );
    card.append(
      textElement("strong", "orientation-preview-title", link.dataset.orientationConcept),
    );
    card.append(
      textElement("p", "orientation-preview-body", link.dataset.orientationDefinition),
    );
    card.append(
      textElement(
        "small",
        "orientation-preview-hint",
        "The link opens optional external background; it is not VSTD authority.",
      ),
    );
    requestAnimationFrame(() => position(link));
  };

  const show = (link) => {
    clearTimeout(timer);
    activeLink = link;
    link.setAttribute("aria-describedby", card.id);
    card.hidden = false;
    render(link);
  };

  const hide = (link) => {
    if (
      activeLink !== link ||
      link.matches(":hover") ||
      document.activeElement === link
    ) {
      return;
    }
    link.removeAttribute("aria-describedby");
    activeLink = null;
    card.hidden = true;
  };

  for (const link of links) {
    link.addEventListener("mouseenter", () => {
      clearTimeout(timer);
      timer = setTimeout(() => show(link), 250);
    });
    link.addEventListener("mouseleave", () => {
      clearTimeout(timer);
      timer = setTimeout(() => hide(link), 120);
    });
    link.addEventListener("focus", () => show(link));
    link.addEventListener("blur", () => hide(link));
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && activeLink) {
      const link = activeLink;
      link.blur();
      hide(link);
    }
  });
  window.addEventListener("resize", () => activeLink && position(activeLink));
})();
