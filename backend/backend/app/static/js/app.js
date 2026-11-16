console.log("DAT250 SecureApp UI ready");

// Inline scripts were removed from the templates so a strict Content-Security-Policy
// (script-src 'self' + CDN) can be enforced. The initialisation lives here instead.
if (window.dayjs && window.dayjs_plugin_relativeTime) {
  dayjs.extend(dayjs_plugin_relativeTime);
}

(function () {
  const currentPath = window.location.pathname || "/";
  const links = document.querySelectorAll(".navbar .nav-link");
  links.forEach((link) => {
    const href = link.getAttribute("href");
    if (!href) return;
    if (href !== "/" && currentPath.startsWith(href)) {
      link.classList.add("active");
    } else if (href === currentPath) {
      link.classList.add("active");
    }
  });
})();
