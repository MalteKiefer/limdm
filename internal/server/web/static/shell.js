// Remote shell terminal: xterm.js in the page, a WebSocket to the server.
// Binary messages are terminal output, text messages are status updates.
(function () {
  "use strict";
  var el = document.getElementById("terminal");
  var status = document.getElementById("shell-status");
  if (!el || !window.Terminal) return;
  var term = new window.Terminal({ cursorBlink: true, convertEol: false, scrollback: 5000 });
  var fit = window.FitAddon ? new window.FitAddon.FitAddon() : null;
  if (fit) term.loadAddon(fit);
  term.open(el);
  // the canvas renderer needs no inline styles, which the CSP forbids
  if (window.CanvasAddon) term.loadAddon(new window.CanvasAddon.CanvasAddon());
  if (fit) fit.fit();
  var proto = location.protocol === "https:" ? "wss://" : "ws://";
  var ws = new WebSocket(proto + location.host + el.dataset.ws);
  ws.binaryType = "arraybuffer";
  var send = function (obj) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  };
  var resize = function () {
    if (fit) fit.fit();
    send({ r: [term.cols, term.rows] });
  };
  ws.onmessage = function (ev) {
    if (typeof ev.data === "string") {
      if (ev.data === "connected") {
        status.textContent = el.dataset.connected;
        resize();
        term.focus();
      }
      return;
    }
    term.write(new Uint8Array(ev.data));
  };
  ws.onclose = function (ev) {
    status.textContent = el.dataset.ended + " " + (ev.reason || "");
    term.options.disableStdin = true;
  };
  term.onData(function (d) { send({ i: d }); });
  window.addEventListener("resize", resize);
})();
