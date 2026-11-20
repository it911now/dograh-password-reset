/* Adds a "Forgot password?" link under the sign-in form. Loaded by the host app's login page. */
(function () {
  try {
    var LOGIN_PATH = __LOGIN_PATH__;
    var LINK = __LINK__;
    function addLink() {
      try {
        if (location.pathname.replace(/\/+$/, "") !== LOGIN_PATH) return;
        if (document.getElementById("dpr-forgot")) return;
        var field = document.querySelector("form input[type=password]");
        var form = field && field.form;
        if (!form || !form.parentNode) return;
        var a = document.createElement("a");
        a.id = "dpr-forgot";
        a.href = LINK;
        a.textContent = "Forgot password?";
        a.style.cssText = "display:block;margin-top:12px;text-align:center;font-size:14px;";
        form.parentNode.insertBefore(a, form.nextSibling);
      } catch (e) {}
    }
    var observer = new MutationObserver(addLink);
    observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
    addLink();
  } catch (e) {}
})();
