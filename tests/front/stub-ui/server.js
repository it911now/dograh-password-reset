// Stand-in for the Dograh UI: an HTML page whose login form is added by JS (like Next.js),
// a static JS asset, a plain-text asset, and a minimal websocket endpoint (101 + echo).
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");

const page = fs.readFileSync(__dirname + "/page.html");
const asset = fs.readFileSync(__dirname + "/app.js");

http.createServer((req, res) => {
  if (req.url === "/auth/login" || req.url === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    return res.end(page);
  }
  if (req.url === "/_next/static/app.js") {
    res.writeHead(200, { "content-type": "application/javascript" });
    return res.end(asset);
  }
  if (req.url === "/_next/static/note.txt") { // non-HTML body containing the literal marker
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end("not a page: </body> stays as is\n");
  }
  if (req.url === "/echo-proto") {
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end(String(req.headers["x-forwarded-proto"]));
  }
  if (req.url === "/big-headers") { // ~12k of response headers, over nginx's default buffer
    res.writeHead(200, { "content-type": "text/plain", link: "<" + "a".repeat(12000) + ">; rel=preload" });
    return res.end("ok");
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
}).on("upgrade", (req, socket) => {
  const accept = crypto.createHash("sha1")
    .update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
  socket.on("data", (d) => socket.write(d)); // raw echo is enough to prove the tunnel stays open
  socket.on("error", () => {});
}).listen(3010);
