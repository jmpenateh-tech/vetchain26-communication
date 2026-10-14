// =============================================================================
// Communication Service — VetChain 2.10 (mensajería usuario ↔ administración)
//
// Responsabilidad: conversaciones y mensajes entre cada cuenta operativa (fabricante,
// distribuidor, veterinaria) y su administrador responsable. Nada más: no conoce lotes ni
// envíos. Base de datos propia (communication_db).
//
// Modelo: UNA conversación por usuario operativo (su canal con "su administración").
// Quién la atiende NO se guarda en la conversación: se calcula en cada petición con los
// datos de auth-service (administrador responsable actual). Por eso, si el master-admin
// reasigna al usuario, el historial pasa al nuevo administrador y el anterior deja de
// verlo en ese mismo momento (continuidad de la atención, sin copias de los mensajes).
// Usuarios sin administrador -> los atiende la administración general (master-admin).
//
// Acceso (siempre en el backend):
//   - usuario operativo: solo su conversación (/conversations/me...).
//   - admin: solo conversaciones de usuarios de su ámbito (GET /scope de auth-service).
//   - master-admin: todas; abrir la conversación de un usuario que tiene otro
//     administrador queda registrado en la auditoría ("chat.global_access").
//   - El remitente se toma SIEMPRE del token (nadie puede escribir en nombre de otro).
//
// Tiempo real: GET /stream (Server-Sent Events). El evento solo dice "hay novedades en la
// conversación X" (sin contenido); el navegador vuelve a pedir los mensajes con su token,
// así un evento mal dirigido nunca expone texto. Si el flujo se corta (p. ej. Render
// gratis), el frontend sigue funcionando con consultas periódicas.
// =============================================================================
import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { pool, initDb, jsonError, bodyDefault, installErrorHandlers, authenticate, auditTrail, requireRole,
  isAdmin, isMaster, getScope, ScopeError, callService, AUTH_URL, sendAudit, clientIp } from "./common.js";

const app = express();
const PORT = process.env.PORT || 3010;
const MAX_BODY = 2000;
const OPERATIVE = ["fabricante", "distribuidor", "veterinaria"];
// 2.10.2: los gerentes (rol "admin") también tienen su propia conversación, con el
// Administrador (master-admin). CHAT_OWNERS = cuentas que pueden tener "su" conversación.
const CHAT_OWNERS = [...OPERATIVE, "admin"];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use(bodyDefault);

await initDb(`
CREATE TABLE IF NOT EXISTS conversations(
  id UUID PRIMARY KEY,
  user_id INT UNIQUE NOT NULL,
  user_name TEXT NOT NULL,
  user_role TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'abierta',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_message_at TIMESTAMPTZ,
  last_message_preview TEXT,
  last_sender_side TEXT);
CREATE TABLE IF NOT EXISTS messages(
  id BIGSERIAL PRIMARY KEY,
  conversation_id UUID NOT NULL REFERENCES conversations(id),
  sender_id INT NOT NULL,
  sender_name TEXT NOT NULL,
  sender_role TEXT NOT NULL,
  side TEXT NOT NULL CHECK (side IN ('usuario','administracion')),
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  read_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id, id);
CREATE INDEX IF NOT EXISTS idx_conv_last ON conversations(last_message_at DESC);`);

app.get("/", (_, res) => res.json({ service: "communication-service", status: "ok" }));
app.get("/health", async (_, res) => {
  try { await pool.query("select 1"); res.json({ status: "ok" }); }
  catch { res.status(503).json({ status: "down" }); }
});

app.use(auditTrail("communication", [
  ["PATCH", /^\/conversations\/[^/]+\/?$/, "chat.status_changed", (b, r) => ({ target: r.user_name, message: `Marcó la conversación como ${r.status || b.status}` })],
]));
app.use(authenticate);

// -----------------------------------------------------------------------------
// Utilidades
// -----------------------------------------------------------------------------
class Denied extends Error { constructor(status, message) { super(message); this.status = status; } }
const send = (res, e, fallback) => {
  if (e instanceof Denied || e instanceof ScopeError) return jsonError(res, e.status, e.message);
  console.error(e);
  return jsonError(res, 500, fallback);
};
// El lado de un mensaje depende de la conversación: el dueño escribe como "usuario" (aunque
// sea un gerente en su canal con el Administrador); quien atiende, como "administracion".
const side = (req, conv) => (conv && conv.user_id === Number(req.auth.id) ? "usuario" : isAdmin(req) ? "administracion" : "usuario");
const toMsg = (m, me) => ({ id: m.id, conversationId: m.conversation_id, senderId: m.sender_id, senderName: m.sender_name, senderRole: m.sender_role,
  side: m.side, body: m.body, createdAt: m.created_at, readAt: m.read_at, mine: me !== undefined ? m.sender_id === Number(me) : undefined });

// Administrador responsable de la cuenta que llama (operativa), según auth-service.
async function myAdmin(req) {
  // Un gerente siempre habla con el Administrador (master-admin), no con otro gerente.
  if (req.auth.role === "admin") return { applies: true, admin: null, general: true };
  const r = await callService(AUTH_URL, "/me/admin", req, { timeout: 8000 });
  if (!r.ok) throw new Denied(503, "No se pudo identificar a tu gerente. Intenta de nuevo.");
  return r.data; // { applies, admin: {id,name}|null, general }
}

// ¿Puede el que llama acceder a la conversación "c"? Devuelve info del ámbito.
async function access(req, c) {
  if (!c) throw new Denied(404, "Conversación no encontrada");
  if (c.user_id === Number(req.auth.id)) return { owner: true }; // su propia conversación
  if (!isAdmin(req)) throw new Denied(404, "Conversación no encontrada");
  const scope = await getScope(req);
  const u = (scope.users || []).find((x) => x.id === c.user_id);
  if (isMaster(req)) {
    // El master-admin atiende a los usuarios sin administrador; los demás son "acceso global".
    return { global: !!(u && u.adminId), user: u };
  }
  // Un gerente solo atiende a sus usuarios operativos (nunca la conversación de otro gerente).
  if (!u || !OPERATIVE.includes(u.role)) throw new Denied(404, "Conversación no encontrada");
  return { user: u };
}

const globalSeen = new Map(); // master-admin + conversación -> último registro (1 por hora)
function auditGlobal(req, c, u) {
  const key = `${req.auth.id}:${c.id}`;
  if (Date.now() - (globalSeen.get(key) || 0) < 3600_000) return;
  globalSeen.set(key, Date.now());
  sendAudit({ service: "communication", ip: clientIp(req), method: req.method, path: req.originalUrl.split("?")[0], actor_id: req.auth.id, actor_name: req.auth.name, actor_role: req.auth.role,
    action: "chat.global_access", outcome: "ok", severity: "warning", target: c.user_name,
    message: `Consultó la conversación de ${c.user_name} (responsable: ${u?.adminName || "otro gerente"}) con acceso global` });
}

// Límite simple anti-abuso: 30 mensajes por minuto y cuenta.
const sentWindow = new Map();
function rateLimited(userId) {
  const now = Date.now();
  const w = sentWindow.get(userId);
  if (!w || now - w.start > 60_000) { sentWindow.set(userId, { start: now, n: 1 }); return false; }
  return ++w.n > 30;
}

function cleanBody(raw) {
  if (typeof raw !== "string") throw new Denied(400, "Escribe un mensaje");
  const body = raw.replace(/\r\n/g, "\n").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim();
  if (!body) throw new Denied(400, "El mensaje no puede estar vacío");
  if (body.length > MAX_BODY) throw new Denied(400, `El mensaje no puede superar ${MAX_BODY} caracteres`);
  return body;
}

async function insertMessage(req, conv, body) {
  if (rateLimited(Number(req.auth.id))) throw new Denied(429, "Estás enviando mensajes muy rápido. Espera un momento.");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const m = (await client.query(
      `insert into messages(conversation_id,sender_id,sender_name,sender_role,side,body) values($1,$2,$3,$4,$5,$6) returning *`,
      [conv.id, Number(req.auth.id), req.auth.name, req.auth.role, side(req, conv), body])).rows[0];
    await client.query(
      `update conversations set last_message_at=$2, last_message_preview=$3, last_sender_side=$4,
         status=case when $4='usuario' then 'abierta' else status end where id=$1`,
      [conv.id, m.created_at, body.slice(0, 140), m.side]);
    await client.query("COMMIT");
    return m;
  } catch (e) { await client.query("ROLLBACK").catch(() => {}); throw e; }
  finally { client.release(); }
}

// -----------------------------------------------------------------------------
// Tiempo real (SSE): oyentes por cuenta
// -----------------------------------------------------------------------------
const listeners = new Map(); // userId -> Set(res)
const masters = new Set();   // res de master-admins conectados
function notify(userIds, payload) {
  const data = `event: chat\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const id of new Set(userIds.filter((x) => x !== null && x !== undefined).map(Number))) for (const r of listeners.get(id) || []) r.write(data);
  for (const r of masters) r.write(data);
}

app.get("/stream", (req, res) => {
  res.status(200).set({ "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-store", Connection: "keep-alive", "X-Accel-Buffering": "no" });
  res.flushHeaders?.();
  res.write(`event: ready\ndata: {}\n\n`);
  const id = Number(req.auth.id);
  if (isMaster(req)) masters.add(res);
  if (!listeners.has(id)) listeners.set(id, new Set());
  listeners.get(id).add(res);
  const ping = setInterval(() => res.write(": ping\n\n"), 25000);
  req.on("close", () => { clearInterval(ping); listeners.get(id)?.delete(res); masters.delete(res); });
});

// -----------------------------------------------------------------------------
// Usuario operativo: su conversación
// -----------------------------------------------------------------------------
app.get("/conversations/me", requireRole(...CHAT_OWNERS), async (req, res) => {
  try {
    const admin = await myAdmin(req);
    const c = (await pool.query("select * from conversations where user_id=$1", [Number(req.auth.id)])).rows[0] || null;
    const msgs = c ? (await pool.query("select * from messages where conversation_id=$1 order by id", [c.id])).rows : [];
    res.json({ conversation: c ? { id: c.id, status: c.status, createdAt: c.created_at } : null,
      admin: admin.admin, general: admin.general, messages: msgs.map((m) => toMsg(m, req.auth.id)),
      unread: msgs.filter((m) => m.side === "administracion" && !m.read_at).length });
  } catch (e) { send(res, e, "Error consultando tu conversación"); }
});

app.post("/conversations/me/messages", requireRole(...CHAT_OWNERS), async (req, res) => {
  try {
    const body = cleanBody(req.body.body);
    const admin = await myAdmin(req);
    const uid = Number(req.auth.id);
    await pool.query(
      `insert into conversations(id,user_id,user_name,user_role) values($1,$2,$3,$4)
       on conflict(user_id) do update set user_name=excluded.user_name, user_role=excluded.user_role`,
      [crypto.randomUUID(), uid, req.auth.name, req.auth.role]);
    const c = (await pool.query("select * from conversations where user_id=$1", [uid])).rows[0];
    const m = await insertMessage(req, c, body);
    notify([uid, admin.admin?.id], { conversationId: c.id, kind: "message" });
    res.status(201).json(toMsg(m, uid));
  } catch (e) { send(res, e, "No se pudo enviar el mensaje"); }
});

app.post("/conversations/me/read", requireRole(...CHAT_OWNERS), async (req, res) => {
  try {
    const r = await pool.query(
      `update messages set read_at=now() where read_at is null and side='administracion'
         and conversation_id=(select id from conversations where user_id=$1)`, [Number(req.auth.id)]);
    res.json({ read: r.rowCount });
  } catch (e) { send(res, e, "Error marcando los mensajes como leídos"); }
});

// -----------------------------------------------------------------------------
// Administración: bandeja (admin: su ámbito; master-admin: global con filtros)
// -----------------------------------------------------------------------------
app.get("/conversations", requireRole("admin", "master-admin"), async (req, res) => {
  try {
    const master = isMaster(req);
    const scope = await getScope(req, master ? { adminId: req.query.admin_id, userId: req.query.user_id } : {});
    // El Administrador ve también los canales de los gerentes; un gerente, solo a sus usuarios.
    const users = new Map((scope.users || []).filter((u) => OPERATIVE.includes(u.role) || (master && u.role === "admin")).map((u) => [u.id, u]));
    const params = [[...users.keys()]];
    let where = "where c.user_id = any($1::int[])";
    if (req.query.status && ["abierta", "cerrada"].includes(req.query.status)) { params.push(req.query.status); where += ` and c.status=$${params.length}`; }
    if (req.query.unread === "1") where += " and exists (select 1 from messages m where m.conversation_id=c.id and m.side='usuario' and m.read_at is null)";
    for (const [k, op] of [["from", ">="], ["to", "<"]]) {
      if (!req.query[k]) continue;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(String(req.query[k]))) return jsonError(res, 400, "Fecha no válida (AAAA-MM-DD)");
      params.push(String(req.query[k])); where += ` and c.last_message_at ${op} ($${params.length}::date ${k === "to" ? "+ 1" : ""})`;
    }
    const rows = (await pool.query(
      `select c.*, (select count(*)::int from messages m where m.conversation_id=c.id and m.side='usuario' and m.read_at is null) as unread,
              (select count(*)::int from messages m where m.conversation_id=c.id) as total
         from conversations c ${where} order by c.last_message_at desc nulls last limit 1000`, params)).rows;
    res.json(rows.map((c) => {
      const u = users.get(c.user_id);
      return { id: c.id, userId: c.user_id, userName: u?.name || c.user_name, userRole: u?.role || c.user_role, userActive: u?.active ?? true,
        adminId: u?.adminId ?? null, adminName: u?.adminName ?? null, status: c.status, createdAt: c.created_at,
        lastMessageAt: c.last_message_at, lastMessagePreview: c.last_message_preview, lastSenderSide: c.last_sender_side, unread: c.unread, total: c.total };
    }));
  } catch (e) { send(res, e, "Error listando conversaciones"); }
});

async function loadConv(req) {
  if (!UUID_RE.test(req.params.id)) throw new Denied(404, "Conversación no encontrada");
  return (await pool.query("select * from conversations where id=$1", [req.params.id])).rows[0];
}

app.get("/conversations/:id/messages", async (req, res) => {
  try {
    const c = await loadConv(req);
    const a = await access(req, c);
    if (a.global) auditGlobal(req, c, a.user);
    const msgs = (await pool.query("select * from messages where conversation_id=$1 order by id", [c.id])).rows;
    res.json({ conversation: { id: c.id, userId: c.user_id, userName: a.user?.name || c.user_name, userRole: a.user?.role || c.user_role,
      adminName: a.user?.adminName ?? null, status: c.status, createdAt: c.created_at, globalAccess: !!a.global },
      messages: msgs.map((m) => toMsg(m, req.auth.id)) });
  } catch (e) { send(res, e, "Error consultando la conversación"); }
});

app.post("/conversations/:id/messages", async (req, res) => {
  try {
    const body = cleanBody(req.body.body);
    const c = await loadConv(req);
    const a = await access(req, c);
    if (a.global) auditGlobal(req, c, a.user);
    const m = await insertMessage(req, c, body);
    notify([c.user_id, a.user?.adminId], { conversationId: c.id, kind: "message" });
    res.status(201).json(toMsg(m, req.auth.id));
  } catch (e) { send(res, e, "No se pudo enviar el mensaje"); }
});

app.post("/conversations/:id/read", async (req, res) => {
  try {
    const c = await loadConv(req);
    const a = await access(req, c);
    // Cada lado marca como leídos los mensajes del otro lado. El acceso global del
    // master-admin a la conversación de otro administrador no marca nada como leído.
    if (a.global) return res.json({ read: 0 });
    const other = a.owner ? "administracion" : "usuario";
    const r = await pool.query("update messages set read_at=now() where conversation_id=$1 and side=$2 and read_at is null", [c.id, other]);
    if (r.rowCount) notify([c.user_id, a.user?.adminId], { conversationId: c.id, kind: "read" });
    res.json({ read: r.rowCount });
  } catch (e) { send(res, e, "Error marcando los mensajes como leídos"); }
});

app.patch("/conversations/:id", requireRole("admin", "master-admin"), async (req, res) => {
  try {
    const status = req.body.status;
    if (!["abierta", "cerrada"].includes(status)) return jsonError(res, 400, "status debe ser 'abierta' o 'cerrada'");
    const c = await loadConv(req);
    const a = await access(req, c);
    if (a.owner) return jsonError(res, 403, "Solo quien atiende la conversación puede cerrarla o reabrirla");
    if (a.global) auditGlobal(req, c, a.user);
    const r = await pool.query("update conversations set status=$1 where id=$2 returning *", [status, c.id]);
    notify([c.user_id, a.user?.adminId], { conversationId: c.id, kind: "status" });
    res.json({ id: r.rows[0].id, status: r.rows[0].status, user_name: r.rows[0].user_name });
  } catch (e) { send(res, e, "Error actualizando la conversación"); }
});

// Contador para el menú: mensajes sin leer dirigidos a quien llama.
app.get("/unread", async (req, res) => {
  try {
    const mine = async () => (await pool.query(
      `select count(*)::int as n from messages m join conversations c on c.id=m.conversation_id
        where c.user_id=$1 and m.side='administracion' and m.read_at is null`, [Number(req.auth.id)])).rows[0].n;
    if (!isAdmin(req)) {
      const r = await pool.query(
        `select count(*)::int as n from messages m join conversations c on c.id=m.conversation_id
          where c.user_id=$1 and m.side='administracion' and m.read_at is null`, [Number(req.auth.id)]);
      return res.json({ unread: r.rows[0].n });
    }
    // admin: su ámbito. master-admin: solo los usuarios que atiende directamente (sin
    // administrador); lo demás es supervisión, no bandeja propia.
    const scope = await getScope(req);
    // El Administrador atiende además los canales de los gerentes.
    const ids = (scope.users || []).filter((u) => (OPERATIVE.includes(u.role) && (!isMaster(req) || !u.adminId)) || (isMaster(req) && u.role === "admin")).map((u) => u.id);
    const r = await pool.query(
      `select count(*)::int as n, count(distinct m.conversation_id)::int as conversations from messages m join conversations c on c.id=m.conversation_id
        where c.user_id = any($1::int[]) and m.side='usuario' and m.read_at is null`, [ids]);
    // Gerente: bandeja de sus usuarios + respuestas del Administrador en su propio canal.
    const own = req.auth.role === "admin" ? await mine() : 0;
    res.json({ unread: r.rows[0].n + own, inbox: r.rows[0].n, own, conversations: r.rows[0].conversations });
  } catch (e) { send(res, e, "Error consultando los mensajes sin leer"); }
});

installErrorHandlers(app);
app.listen(PORT, () => console.log(`Communication Service http://localhost:${PORT}`));
