"use strict";
// Student OS WebSocket server for the TurboWarp "godslayerakp/ws" extension.
// All messages in both directions are JSON text. Supports wss:// directly
// (SSL_CERT + SSL_KEY) or plain ws behind a TLS-terminating host/proxy.

const WebSocket = require("ws");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 8080);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SSL_CERT = process.env.SSL_CERT; // path to fullchain.pem
const SSL_KEY = process.env.SSL_KEY;   // path to privkey.pem
const DATA_FILE = path.join(__dirname, "data.json");
const BLOCKED = (process.env.BLOCKED_WORDS || "")
  .split(",").map((w) => w.trim().toLowerCase()).filter(Boolean);

const LIM = {
  msgBytes: 16384, text: 1500, pass: 128, files: 50, fileSize: 8000,
  mail: 50, pubEntries: 500, pubValue: 1000, scores: 100, rooms: 10,
  rateCount: 30, rateMs: 10_000, muteMs: 5 * 60_000, saveMs: 500,
  heartbeatMs: 30_000,
};

// ---------- Database (JSON file, debounced atomic saves) ----------
let db = { users: {}, mail: {}, files: {}, pub: {}, scores: {} };
try {
  if (fs.existsSync(DATA_FILE)) {
    db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, "utf8")) };
  }
} catch (e) {
  console.error("Could not read data.json, starting fresh:", e.message);
}

let saveTimer = null;
function saveSoon() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; saveNow(); }, LIM.saveMs);
}
function saveNow() {
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}

// ---------- Helpers ----------
const clients = new Map(); // ws -> state
const online = new Map();  // lowercase name -> ws
const rooms = new Map();   // room -> Set(lowercase names)
const muted = new Map();   // lowercase name -> until timestamp

const key = (s) => String(s).toLowerCase();
const isStr = (v) => typeof v === "string";
const validName = (n) => isStr(n) && /^[A-Za-z0-9_]{3,20}$/.test(n);
const validRoom = (n) => isStr(n) && /^[A-Za-z0-9_-]{1,20}$/.test(n);
const validFile = (n) => isStr(n) && /^[A-Za-z0-9_. -]{1,40}$/.test(n);
const validKey = (n) => isStr(n) && /^[A-Za-z0-9_.-]{1,40}$/.test(n);
const isGuest = (n) => /^guest\d+$/i.test(n);

function filterText(t) {
  let out = t;
  for (const w of BLOCKED) {
    out = out.replace(new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"),
      "*".repeat(w.length));
  }
  return out;
}

function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
const ok = (ws, cmd, extra = {}) => send(ws, { type: "ok", cmd, ...extra });
const err = (ws, cmd, error) => send(ws, { type: "err", cmd, error });
const evt = (event, extra = {}) => ({ type: "evt", event, ...extra });

function hashPassword(pw, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(pw, salt, 32).toString("hex") };
}
function checkPassword(pw, rec) {
  const { hash } = hashPassword(pw, rec.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(rec.hash, "hex"));
}

function sendToUser(name, obj) {
  const ws = online.get(key(name));
  if (ws) send(ws, obj);
  return !!ws;
}
function broadcast(obj) {
  for (const [ws, st] of clients) if (st.user) send(ws, obj);
}

function leaveAllRooms(user) {
  for (const [room, set] of rooms) {
    if (set.delete(key(user))) {
      for (const n of set) sendToUser(n, evt("left", { room, user }));
    }
    if (set.size === 0) rooms.delete(room);
  }
}

function logout(ws) {
  const st = clients.get(ws);
  if (!st || !st.user) return;
  leaveAllRooms(st.user);
  online.delete(key(st.user));
  broadcast(evt("offline", { user: st.user }));
  st.user = null;
}

function login(ws, name) {
  const st = clients.get(ws);
  logout(ws);
  const old = online.get(key(name));
  if (old && old !== ws) {
    send(old, evt("kicked", { reason: "Logged in elsewhere" }));
    old.close(4001, "replaced");
  }
  st.user = name;
  online.set(key(name), ws);
  broadcast(evt("online", { user: name }));
}

function isMuted(user) {
  const until = muted.get(key(user));
  if (!until) return false;
  if (Date.now() > until) { muted.delete(key(user)); return false; }
  return true;
}

// Returns a cleaned chat string, or null if invalid.
function chatText(v, max = LIM.text) {
  if (!isStr(v)) return null;
  const t = v.replace(/\0/g, "").trim();
  if (!t || t.length > max) return null;
  return filterText(t);
}

// ---------- Commands ----------
// auth: must be logged in. reg: must be a registered (non-guest) account.
const commands = {
  ping: { run: (ws) => ok(ws, "ping", { time: Date.now() }) },
  time: { run: (ws) => ok(ws, "time", { iso: new Date().toISOString() }) },

  guest: { run(ws) {
    let name;
    do { name = "Guest" + crypto.randomInt(1000, 9999); }
    while (online.has(key(name)));
    login(ws, name);
    ok(ws, "guest", { name });
  }},

  register: { run(ws, st, m) {
    if (!validName(m.name)) return err(ws, "register", "Name must be 3-20 letters, numbers or _");
    if (!isStr(m.pass) || m.pass.length < 6 || m.pass.length > LIM.pass) return err(ws, "register", "Password must be 6-128 characters");
    if (db.users[key(m.name)] || isGuest(m.name)) return err(ws, "register", "Name taken");
    db.users[key(m.name)] = { name: m.name, ...hashPassword(m.pass), created: Date.now() };
    saveSoon();
    login(ws, m.name);
    ok(ws, "register", { name: m.name });
  }},

  login: { run(ws, st, m) {
    const rec = isStr(m.name) && isStr(m.pass) ? db.users[key(m.name)] : null;
    if (!rec || !checkPassword(m.pass, rec)) return err(ws, "login", "Wrong name or password");
    login(ws, rec.name);
    ok(ws, "login", { name: rec.name, unreadMail: (db.mail[key(rec.name)] || []).length });
  }},

  logout: { run(ws) { logout(ws); ok(ws, "logout"); } },

  who: { auth: true, run(ws) {
    const users = [...online.values()].map((w) => clients.get(w).user);
    ok(ws, "who", { users });
  }},

  rooms: { auth: true, run(ws) {
    ok(ws, "rooms", { rooms: [...rooms].map(([name, s]) => ({ name, count: s.size })) });
  }},

  chat: { auth: true, run(ws, st, m) {
    if (isMuted(st.user)) return err(ws, "chat", "You are muted");
    const text = chatText(m.text);
    if (!text) return err(ws, "chat", "Bad message");
    broadcast(evt("chat", { from: st.user, text }));
    ok(ws, "chat");
  }},

  join: { auth: true, run(ws, st, m) {
    if (!validRoom(m.room)) return err(ws, "join", "Bad room name");
    const mine = [...rooms.values()].filter((s) => s.has(key(st.user))).length;
    if (!rooms.has(m.room)) rooms.set(m.room, new Set());
    const set = rooms.get(m.room);
    if (!set.has(key(st.user)) && mine >= LIM.rooms) return err(ws, "join", "Too many rooms");
    set.add(key(st.user));
    for (const n of set) if (n !== key(st.user)) sendToUser(n, evt("joined", { room: m.room, user: st.user }));
    ok(ws, "join", { room: m.room, members: [...set] });
  }},

  leave: { auth: true, run(ws, st, m) {
    const set = rooms.get(m.room);
    if (!set || !set.delete(key(st.user))) return err(ws, "leave", "Not in that room");
    for (const n of set) sendToUser(n, evt("left", { room: m.room, user: st.user }));
    if (set.size === 0) rooms.delete(m.room);
    ok(ws, "leave", { room: m.room });
  }},

  roommsg: { auth: true, run(ws, st, m) {
    if (isMuted(st.user)) return err(ws, "roommsg", "You are muted");
    const set = rooms.get(m.room);
    if (!set || !set.has(key(st.user))) return err(ws, "roommsg", "Join the room first");
    const text = chatText(m.text);
    if (!text) return err(ws, "roommsg", "Bad message");
    for (const n of set) sendToUser(n, evt("roommsg", { room: m.room, from: st.user, text }));
    ok(ws, "roommsg", { room: m.room });
  }},

  dm: { auth: true, run(ws, st, m) {
    if (isMuted(st.user)) return err(ws, "dm", "You are muted");
    const text = chatText(m.text);
    if (!text || !isStr(m.to)) return err(ws, "dm", "Bad message");
    if (!sendToUser(m.to, evt("dm", { from: st.user, text }))) return err(ws, "dm", "User not online (use mail)");
    ok(ws, "dm", { to: m.to });
  }},

  mail: { auth: true, run(ws, st, m) {
    if (isMuted(st.user)) return err(ws, "mail", "You are muted");
    const rec = isStr(m.to) ? db.users[key(m.to)] : null;
    if (!rec) return err(ws, "mail", "No such registered user");
    const text = chatText(m.text, 1000);
    if (!text) return err(ws, "mail", "Bad message");
    const box = (db.mail[key(rec.name)] ||= []);
    if (box.length >= LIM.mail) return err(ws, "mail", "Inbox full");
    box.push({ from: st.user, text, time: Date.now() });
    saveSoon();
    sendToUser(rec.name, evt("newmail", { from: st.user }));
    ok(ws, "mail", { to: rec.name });
  }},

  inbox: { auth: true, run(ws, st) {
    const mail = (db.mail[key(st.user)] || []).map((x, i) => ({
      id: i + 1, from: x.from, text: x.text, time: new Date(x.time).toISOString(),
    }));
    ok(ws, "inbox", { mail });
  }},

  clearmail: { auth: true, run(ws, st) {
    delete db.mail[key(st.user)];
    saveSoon();
    ok(ws, "clearmail");
  }},

  fssave: { auth: true, reg: true, run(ws, st, m) {
    if (!validFile(m.file)) return err(ws, "fssave", "Bad file name");
    if (!isStr(m.content) || m.content.length > LIM.fileSize) return err(ws, "fssave", "File too large or not text");
    const files = (db.files[key(st.user)] ||= {});
    if (!(m.file in files) && Object.keys(files).length >= LIM.files) return err(ws, "fssave", "Too many files");
    files[m.file] = m.content;
    saveSoon();
    ok(ws, "fssave", { file: m.file });
  }},

  fsload: { auth: true, reg: true, run(ws, st, m) {
    const files = db.files[key(st.user)] || {};
    if (!validFile(m.file) || !(m.file in files)) return err(ws, "fsload", "No such file");
    ok(ws, "fsload", { file: m.file, content: files[m.file] });
  }},

  fslist: { auth: true, reg: true, run(ws, st) {
    ok(ws, "fslist", { files: Object.keys(db.files[key(st.user)] || {}) });
  }},

  fsdelete: { auth: true, reg: true, run(ws, st, m) {
    const files = db.files[key(st.user)] || {};
    if (!validFile(m.file) || !(m.file in files)) return err(ws, "fsdelete", "No such file");
    delete files[m.file];
    saveSoon();
    ok(ws, "fsdelete", { file: m.file });
  }},

  setpub: { auth: true, reg: true, run(ws, st, m) {
    if (!validKey(m.key)) return err(ws, "setpub", "Bad key");
    if (!isStr(m.value) || m.value.length > LIM.pubValue) return err(ws, "setpub", "Value too long");
    if (!(m.key in db.pub) && Object.keys(db.pub).length >= LIM.pubEntries) return err(ws, "setpub", "Store full");
    if (db.pub[m.key] && db.pub[m.key].owner !== key(st.user)) return err(ws, "setpub", "Key owned by someone else");
    db.pub[m.key] = { owner: key(st.user), value: filterText(m.value) };
    saveSoon();
    ok(ws, "setpub", { key: m.key });
  }},

  getpub: { auth: true, run(ws, st, m) {
    if (!validKey(m.key) || !db.pub[m.key]) return err(ws, "getpub", "No such key");
    ok(ws, "getpub", { key: m.key, value: db.pub[m.key].value });
  }},

  score: { auth: true, reg: true, run(ws, st, m) {
    const score = Number(m.score);
    if (!isStr(m.game) || !/^[A-Za-z0-9_-]{1,20}$/.test(m.game) || !Number.isFinite(score)) return err(ws, "score", "Bad game or score");
    const board = (db.scores[m.game] ||= []);
    const mine = board.find((e) => e.user === st.user);
    if (mine) { if (score > mine.score) mine.score = score; }
    else board.push({ user: st.user, score });
    board.sort((a, b) => b.score - a.score);
    board.length = Math.min(board.length, LIM.scores);
    saveSoon();
    ok(ws, "score", { game: m.game });
  }},

  top: { auth: true, run(ws, st, m) {
    const n = Math.max(1, Math.min(Number(m.count) || 10, 25));
    const board = isStr(m.game) ? (db.scores[m.game] || []).slice(0, n) : [];
    ok(ws, "top", { game: m.game, scores: board });
  }},

  admin: { run(ws, st, m) {
    if (!ADMIN_PASSWORD) return err(ws, "admin", "Admin disabled");
    if (!isStr(m.pass)) return err(ws, "admin", "Denied");
    const a = Buffer.from(m.pass), b = Buffer.from(ADMIN_PASSWORD);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return err(ws, "admin", "Denied");
    const action = isStr(m.action) ? m.action.toLowerCase() : "";
    const target = isStr(m.user) ? m.user : "";
    if (action === "kick") {
      const t = online.get(key(target));
      if (!t) return err(ws, "admin", "User not online");
      send(t, evt("kicked", { reason: "Removed by admin" }));
      t.close(4002, "kicked");
    } else if (action === "mute") {
      muted.set(key(target), Date.now() + LIM.muteMs);
    } else if (action === "unmute") {
      muted.delete(key(target));
    } else return err(ws, "admin", "Use kick, mute or unmute");
    ok(ws, "admin", { action, user: target });
  }},
};

// ---------- Server (WSS) ----------
function handleHttp(req, res) {
  // Simple health check so hosts and uptime monitors can see the server is alive.
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("ok");
}

let httpServer;
if (SSL_CERT && SSL_KEY) {
  // Direct TLS: this process serves wss:// itself.
  httpServer = https.createServer(
    { cert: fs.readFileSync(SSL_CERT), key: fs.readFileSync(SSL_KEY) },
    handleHttp
  );
  // Pick up renewed certificates (e.g. Let's Encrypt) without a restart.
  fs.watchFile(SSL_CERT, { interval: 60_000 }, () => {
    try {
      httpServer.setSecureContext({
        cert: fs.readFileSync(SSL_CERT),
        key: fs.readFileSync(SSL_KEY),
      });
      console.log("TLS certificate reloaded");
    } catch (e) {
      console.error("Certificate reload failed:", e.message);
    }
  });
} else {
  // No certs given: plain HTTP. Only use this behind a host/proxy that
  // terminates TLS for you (Render, Fly.io, Railway, Caddy, nginx, etc.).
  httpServer = http.createServer(handleHttp);
  console.warn("SSL_CERT/SSL_KEY not set: running without TLS. Use a TLS-terminating host or proxy for wss://");
}

const wss = new WebSocket.Server({ server: httpServer, maxPayload: LIM.msgBytes });

wss.on("connection", (ws) => {
  const st = { user: null, hits: [], alive: true };
  clients.set(ws, st);
  send(ws, evt("welcome"));

  ws.on("pong", () => { st.alive = true; });

  ws.on("message", (data, isBinary) => {
    if (isBinary) return err(ws, null, "Text only");

    const now = Date.now();
    st.hits = st.hits.filter((t) => now - t < LIM.rateMs);
    if (st.hits.push(now) > LIM.rateCount) return err(ws, null, "Slow down");

    let m;
    try { m = JSON.parse(String(data)); } catch { return err(ws, null, "Invalid JSON"); }
    if (!m || typeof m !== "object" || Array.isArray(m) || !isStr(m.cmd)) {
      return err(ws, null, "Missing cmd");
    }

    const name = m.cmd.toLowerCase();
    const cmd = Object.prototype.hasOwnProperty.call(commands, name) ? commands[name] : null;
    if (!cmd) return err(ws, name, "Unknown command");
    if (cmd.auth && !st.user) return err(ws, name, "Log in first");
    if (cmd.reg && isGuest(st.user)) return err(ws, name, "Guests can't use this; register an account");

    try { cmd.run(ws, st, m); }
    catch (e) { console.error(e); err(ws, name, "Server error"); }
  });

  ws.on("close", () => { logout(ws); clients.delete(ws); });
  ws.on("error", () => {});
});

// Drop dead connections
const heartbeat = setInterval(() => {
  for (const [ws, st] of clients) {
    if (!st.alive) { ws.terminate(); continue; }
    st.alive = false;
    ws.ping();
  }
}, LIM.heartbeatMs);

function shutdown() {
  console.log("Shutting down...");
  clearInterval(heartbeat);
  if (saveTimer) clearTimeout(saveTimer);
  saveNow();
  for (const ws of clients.keys()) ws.close(1001, "server shutting down");
  wss.close(() => httpServer.close(() => process.exit(0)));
  setTimeout(() => process.exit(0), 2000);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

httpServer.listen(PORT, () => {
  const proto = SSL_CERT && SSL_KEY ? "wss" : "ws (behind a TLS proxy for wss)";
  console.log(`Student OS server listening on port ${PORT} as ${proto}`);
});
