try {
  document.documentElement.dataset.theme = localStorage.getItem("hy2-theme") || "light";
} catch {
  document.documentElement.dataset.theme = "light";
}
