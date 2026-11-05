/* Applies the saved theme before first paint to avoid a flash. Kept external so the CSP can forbid inline scripts. */
(function () {
  try {
    var p = JSON.parse(localStorage.getItem('osint.prefs.v3') || '{}');
    var t = p.theme === 'light' || p.theme === 'dark' ? p.theme : '';
    if (t) document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* storage unavailable: fall back to system preference via CSS */ }
})();
