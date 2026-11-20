// Adds a login form after load, like a client-rendered page.
setTimeout(function () {
  var f = document.createElement("form");
  f.innerHTML = '<input type="email"><input type="password"><button>Sign in</button>';
  document.getElementById("root").appendChild(f);
}, 50);
