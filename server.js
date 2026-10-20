'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { db, tx, UPLOAD_DIR, DEFAULT_DEPENDENCIAS, getConfig, setConfig, hashSecret, verifySecret, randomKey } = require('./lib/db');
const { HttpError, readJson, readMultipart, parseCookies, sendJson, serveStatic, makeLimiter, clientIp } = require('./lib/http');
const { todayStr, nowIso, addBiz, bizDiff } = require('./lib/util');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_MS = 8 * 60 * 60 * 1000;

// Plazos en días hábiles (Ley 1755 de 2015, art. 14). Ajuste según la norma aplicable a su entidad.
const TIPOS = {
  peticion: { nombre: 'Petición', dias: 15 },
  queja: { nombre: 'Queja', dias: 15 },
  reclamo: { nombre: 'Reclamo', dias: 15 },
  sugerencia: { nombre: 'Sugerencia', dias: 15 },
  info: { nombre: 'Solicitud de información o documentos', dias: 10 },
  consulta: { nombre: 'Consulta', dias: 30 },
};
const ESTADOS = { radicado: 'Radicado', tramite: 'En trámite', respondido: 'Respondido', cerrado: 'Cerrado' };
const ABIERTOS = ['radicado', 'tramite'];

const MAX_FILES = 3;
const MAX_FILE = 5 * 1024 * 1024;
const MAGIC = {
  pdf: (b) => b.subarray(0, 4).toString('latin1') === '%PDF',
  png: (b) => b.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])),
  jpg: (b) => b[0] === 0xff && b[1] === 0xd8,
  jpeg: (b) => b[0] === 0xff && b[1] === 0xd8,
  docx: (b) => b[0] === 0x50 && b[1] === 0x4b,
  xlsx: (b) => b[0] === 0x50 && b[1] === 0x4b,
};

const limitLogin = makeLimiter(10, 10 * 60 * 1000);
const limitConsulta = makeLimiter(15, 10 * 60 * 1000);
const limitRadicar = makeLimiter(20, 60 * 60 * 1000);

// ---------- Utilidades ----------
const q = (sql) => db.prepare(sql);
const clean = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);
const dependencias = () => getConfig('dependencias', DEFAULT_DEPENDENCIAS);
const entidad = () => getConfig('entidad', 'Nombre de la entidad');

function bootstrapAdmin() {
  const n = q('SELECT COUNT(*) AS n FROM usuarios').get().n;
  if (n > 0) return;
  const email = (process.env.ADMIN_EMAIL || 'admin@entidad.local').toLowerCase();
  const generated = !process.env.ADMIN_PASSWORD;
  const password = process.env.ADMIN_PASSWORD || randomKey(12);
  q('INSERT INTO usuarios (nombre, email, pass_hash, rol, creado) VALUES (?,?,?,?,?)')
    .run('Administrador', email, hashSecret(password), 'admin', nowIso());
  console.log('\n=== Usuario administrador creado ===');
  console.log('Correo:     ' + email);
  console.log('Contraseña: ' + (generated ? password + '   (cámbiela al ingresar)' : '(la definida en ADMIN_PASSWORD)'));
  console.log('Ingrese en /gestion\n');
}

function isSecure(req) {
  return !!req.socket.encrypted || (process.env.TRUST_PROXY === '1' && req.headers['x-forwarded-proto'] === 'https');
}
function setSessionCookie(req, res, token, maxAgeSec) {
  const parts = [`sid=${token}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${maxAgeSec}`];
  if (isSecure(req)) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function currentUser(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;
  const th = crypto.createHash('sha256').update(sid).digest('hex');
  const row = q(`SELECT u.id, u.nombre, u.email, u.rol, u.dependencia FROM sesiones s
                 JOIN usuarios u ON u.id = s.usuario_id
                 WHERE s.token_hash = ? AND s.expira > ? AND u.activo = 1`).get(th, Date.now());
  return row || null;
}
function requireUser(req) {
  const u = currentUser(req);
  if (!u) throw new HttpError(401, 'Debe iniciar sesión.');
  return u;
}
function requireAdmin(req) {
  const u = requireUser(req);
  if (u.rol !== 'admin') throw new HttpError(403, 'Solo el administrador puede hacer esto.');
  return u;
}

// Un funcionario con dependencia ve los casos de su dependencia y los que tiene asignados. El admin ve todo.
function visibleClause(user) {
  if (user.rol === 'admin' || !user.dependencia) return { sql: '1=1', params: [] };
  return { sql: '(c.dependencia = ? OR c.asignado_a = ?)', params: [user.dependencia, user.id] };
}

function casoOut(c, includePrivate) {
  const abierto = ABIERTOS.includes(c.estado);
  const out = {
    radicado: c.radicado, tipo: c.tipo, tipo_nombre: TIPOS[c.tipo]?.nombre || c.tipo,
    asunto: c.asunto, descripcion: c.descripcion, dependencia: c.dependencia,
    estado: c.estado, estado_nombre: ESTADOS[c.estado] || c.estado,
    creado: c.creado, vence: c.vence, actualizado: c.actualizado,
    respuesta: c.respuesta, respondido_en: c.respondido_en,
    dias: abierto ? bizDiff(todayStr(), c.vence) : null,
  };
  if (includePrivate) {
    out.nombre = c.nombre; out.contacto = c.contacto;
    out.asignado_a = c.asignado_a; out.asignado_nombre = c.asignado_nombre || '';
  }
  return out;
}

function addEvento(casoId, estado, nota, publico, usuarioId) {
  q('INSERT INTO eventos (caso_id, t, estado, nota, publico, usuario_id) VALUES (?,?,?,?,?,?)')
    .run(casoId, nowIso(), estado, nota, publico ? 1 : 0, usuarioId || null);
}

function getCaso(radicado, user) {
  const v = visibleClause(user);
  const c = q(`SELECT c.*, u.nombre AS asignado_nombre FROM casos c LEFT JOIN usuarios u ON u.id = c.asignado_a
               WHERE c.radicado = ? AND ${v.sql}`).get(radicado, ...v.params);
  if (!c) throw new HttpError(404, 'No se encontró la solicitud.');
  return c;
}

const csvCell = (v) => {
  let s = String(v == null ? '' : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // evita fórmulas al abrir en Excel
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};

// ---------- Rutas ----------
const routes = [];
const route = (method, pattern, handler) => routes.push({ method, re: new RegExp('^' + pattern + '$'), handler });

// Públicas
route('GET', '/api/publico', async () => ({
  entidad: entidad(), dependencias: dependencias(),
  tipos: Object.entries(TIPOS).map(([k, v]) => ({ clave: k, nombre: v.nombre, dias: v.dias })),
}));

route('POST', '/api/radicar', async (req) => {
  if (!limitRadicar(clientIp(req))) throw new HttpError(429, 'Demasiadas solicitudes desde su conexión. Intente más tarde.');
  const { fields, files } = await readMultipart(req, MAX_FILES * MAX_FILE + 200 * 1024);
  const tipo = clean(fields.tipo, 20);
  const dep = clean(fields.dependencia, 80);
  const asunto = clean(fields.asunto, 120);
  const descripcion = clean(fields.descripcion, 4000);
  if (!TIPOS[tipo]) throw new HttpError(400, 'Elija un tipo de solicitud.');
  if (!dependencias().includes(dep)) throw new HttpError(400, 'Elija una dependencia.');
  if (asunto.length < 5) throw new HttpError(400, 'El asunto necesita al menos 5 caracteres.');
  if (descripcion.length < 20) throw new HttpError(400, 'La descripción necesita al menos 20 caracteres.');
  const adj = files.filter((f) => f.field === 'adjuntos');
  if (adj.length > MAX_FILES) throw new HttpError(400, `Máximo ${MAX_FILES} archivos adjuntos.`);
  for (const f of adj) {
    const ext = path.extname(f.filename).slice(1).toLowerCase();
    if (!MAGIC[ext] || !MAGIC[ext](f.data)) throw new HttpError(400, 'Solo se aceptan archivos PDF, PNG, JPG, DOCX o XLSX.');
    if (f.data.length > MAX_FILE) throw new HttpError(400, 'Cada archivo puede pesar máximo 5 MB.');
  }

  const clave = randomKey(6);
  const hoy = todayStr();
  const creado = nowIso();
  const vence = addBiz(hoy, TIPOS[tipo].dias);
  const saved = [];
  let radicado;
  try {
    radicado = tx(() => {
      const anio = Number(hoy.slice(0, 4));
      const n = q('INSERT INTO consecutivos (anio, n) VALUES (?, 1) ON CONFLICT(anio) DO UPDATE SET n = n + 1 RETURNING n').get(anio).n;
      const rad = `PQRS-${anio}-${String(n).padStart(6, '0')}`;
      const info = q(`INSERT INTO casos (radicado, tipo, asunto, descripcion, dependencia, nombre, contacto, clave_hash, estado, creado, fecha, vence, actualizado)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(rad, tipo, asunto, descripcion, dep, clean(fields.nombre, 80), clean(fields.contacto, 80),
          hashSecret(clave), 'radicado', creado, hoy, vence, creado);
      const id = Number(info.lastInsertRowid);
      addEvento(id, 'radicado', 'Solicitud radicada', true, null);
      for (const f of adj) {
        const ext = path.extname(f.filename).slice(1).toLowerCase();
        const stored = crypto.randomBytes(16).toString('hex') + '.' + ext;
        fs.writeFileSync(path.join(UPLOAD_DIR, stored), f.data);
        saved.push(stored);
        q('INSERT INTO adjuntos (caso_id, nombre, archivo, tam, creado) VALUES (?,?,?,?,?)')
          .run(id, clean(path.basename(f.filename), 120), stored, f.data.length, creado);
      }
      return rad;
    });
  } catch (e) {
    for (const s of saved) fs.rmSync(path.join(UPLOAD_DIR, s), { force: true });
    throw e;
  }
  return { radicado, clave, vence, creado, tipo_nombre: TIPOS[tipo].nombre, dependencia: dep };
});

route('POST', '/api/consultar', async (req) => {
  if (!limitConsulta(clientIp(req))) throw new HttpError(429, 'Demasiadas consultas seguidas. Espere unos minutos.');
  const body = await readJson(req);
  const rad = clean(body.radicado, 40).toUpperCase().replace(/\s+/g, '');
  const clave = clean(body.clave, 10).toUpperCase();
  const c = rad ? q('SELECT * FROM casos WHERE radicado = ?').get(rad) : null;
  const ok = verifySecret(clave, c ? c.clave_hash : 'aa:bb') && c; // siempre calcula el hash
  if (!ok) throw new HttpError(404, 'No encontramos una solicitud con esos datos. Revise que estén bien escritos.');
  const eventos = q('SELECT t, estado, nota FROM eventos WHERE caso_id = ? AND publico = 1 ORDER BY id').all(c.id);
  const adjuntos = q('SELECT nombre, tam FROM adjuntos WHERE caso_id = ? ORDER BY id').all(c.id);
  return { caso: casoOut(c, false), eventos, adjuntos };
});

// Sesión
route('POST', '/api/login', async (req, res) => {
  if (!limitLogin(clientIp(req))) throw new HttpError(429, 'Demasiados intentos. Espere unos minutos.');
  const b = await readJson(req);
  const email = clean(b.email, 120).toLowerCase();
  const u = q('SELECT * FROM usuarios WHERE email = ? AND activo = 1').get(email);
  const ok = verifySecret(String(b.password || ''), u ? u.pass_hash : 'aa:bb');
  if (!u || !ok) throw new HttpError(401, 'Correo o contraseña incorrectos.');
  q('DELETE FROM sesiones WHERE expira < ?').run(Date.now());
  const token = crypto.randomBytes(32).toString('hex');
  q('INSERT INTO sesiones (token_hash, usuario_id, expira) VALUES (?,?,?)')
    .run(crypto.createHash('sha256').update(token).digest('hex'), u.id, Date.now() + SESSION_MS);
  setSessionCookie(req, res, token, SESSION_MS / 1000);
  return { ok: true };
});
route('POST', '/api/logout', async (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) q('DELETE FROM sesiones WHERE token_hash = ?').run(crypto.createHash('sha256').update(sid).digest('hex'));
  setSessionCookie(req, res, '', 0);
  return { ok: true };
});
route('GET', '/api/yo', async (req) => {
  const u = currentUser(req);
  if (!u) return { usuario: null };
  return {
    usuario: u, entidad: entidad(), dependencias: dependencias(),
    tipos: Object.entries(TIPOS).map(([k, v]) => ({ clave: k, nombre: v.nombre, dias: v.dias })),
    estados: Object.entries(ESTADOS).map(([k, v]) => ({ clave: k, nombre: v })),
    usuarios: q('SELECT id, nombre, dependencia FROM usuarios WHERE activo = 1 ORDER BY nombre').all(),
  };
});
route('POST', '/api/yo/clave', async (req) => {
  const u = requireUser(req);
  const b = await readJson(req);
  const row = q('SELECT pass_hash FROM usuarios WHERE id = ?').get(u.id);
  if (!verifySecret(String(b.actual || ''), row.pass_hash)) throw new HttpError(400, 'La contraseña actual no es correcta.');
  const nueva = String(b.nueva || '');
  if (nueva.length < 10) throw new HttpError(400, 'La contraseña nueva necesita al menos 10 caracteres.');
  q('UPDATE usuarios SET pass_hash = ? WHERE id = ?').run(hashSecret(nueva), u.id);
  return { ok: true };
});

// Bandeja
route('GET', '/api/casos', async (req, _res, url) => {
  const u = requireUser(req);
  const v = visibleClause(u);
  const where = [v.sql];
  const params = [...v.params];
  const p = url.searchParams;
  if (p.get('estado') && ESTADOS[p.get('estado')]) { where.push('c.estado = ?'); params.push(p.get('estado')); }
  if (p.get('abiertas') === '1') where.push("c.estado IN ('radicado','tramite')");
  if (p.get('tipo') && TIPOS[p.get('tipo')]) { where.push('c.tipo = ?'); params.push(p.get('tipo')); }
  if (p.get('asignado') === 'yo') { where.push('c.asignado_a = ?'); params.push(u.id); }
  if (p.get('asignado') === 'nadie') where.push('c.asignado_a IS NULL');
  const term = clean(p.get('q'), 80);
  if (term) {
    where.push("(c.radicado LIKE ? ESCAPE '\\' OR c.asunto LIKE ? ESCAPE '\\')");
    const like = '%' + term.replace(/[\\%_]/g, '\\$&') + '%';
    params.push(like, like);
  }
  const rows = q(`SELECT c.*, u.nombre AS asignado_nombre FROM casos c LEFT JOIN usuarios u ON u.id = c.asignado_a
                  WHERE ${where.join(' AND ')}
                  ORDER BY (c.estado IN ('radicado','tramite')) DESC,
                           CASE WHEN c.estado IN ('radicado','tramite') THEN c.vence END ASC,
                           c.creado DESC LIMIT 500`).all(...params);
  return { casos: rows.map((c) => casoOut(c, true)) };
});

route('GET', '/api/stats', async (req) => {
  const u = requireUser(req);
  const v = visibleClause(u);
  const rows = q(`SELECT c.estado, c.vence, c.tipo FROM casos c WHERE ${v.sql}`).all(...v.params);
  const hoy = todayStr();
  const s = { total: rows.length, sin_tomar: 0, abiertas: 0, por_vencer: 0, vencidas: 0, respondidas: 0 };
  for (const r of rows) {
    if (r.estado === 'radicado') s.sin_tomar++;
    if (ABIERTOS.includes(r.estado)) {
      s.abiertas++;
      const d = bizDiff(hoy, r.vence);
      if (d < 0) s.vencidas++; else if (d <= 3) s.por_vencer++;
    } else s.respondidas++;
  }
  return s;
});

route('GET', '/api/casos/([A-Z0-9-]+)', async (req, _res, _url, m) => {
  const u = requireUser(req);
  const c = getCaso(m[1], u);
  return {
    caso: casoOut(c, true),
    eventos: q(`SELECT e.t, e.estado, e.nota, e.publico, us.nombre AS usuario FROM eventos e
                LEFT JOIN usuarios us ON us.id = e.usuario_id WHERE e.caso_id = ? ORDER BY e.id`).all(c.id),
    adjuntos: q('SELECT id, nombre, tam FROM adjuntos WHERE caso_id = ? ORDER BY id').all(c.id),
  };
});

route('PATCH', '/api/casos/([A-Z0-9-]+)', async (req, _res, _url, m) => {
  const u = requireUser(req);
  const c = getCaso(m[1], u);
  const b = await readJson(req);
  const notas = [];
  const sets = [];
  const params = [];
  if (b.estado !== undefined && b.estado !== c.estado) {
    if (!ESTADOS[b.estado]) throw new HttpError(400, 'Estado no válido.');
    sets.push('estado = ?'); params.push(b.estado);
    notas.push('Estado: ' + ESTADOS[b.estado]);
    if (b.estado === 'respondido' && !c.respondido_en) { sets.push('respondido_en = ?'); params.push(todayStr()); }
  }
  if (b.dependencia !== undefined && b.dependencia !== c.dependencia) {
    if (!dependencias().includes(b.dependencia)) throw new HttpError(400, 'Dependencia no válida.');
    sets.push('dependencia = ?'); params.push(b.dependencia);
    notas.push('Reasignada a ' + b.dependencia);
  }
  if (b.asignado_a !== undefined && (b.asignado_a || null) !== c.asignado_a) {
    let nombre = 'sin asignar';
    if (b.asignado_a) {
      const t = q('SELECT nombre FROM usuarios WHERE id = ? AND activo = 1').get(Number(b.asignado_a));
      if (!t) throw new HttpError(400, 'La persona elegida no existe.');
      nombre = t.nombre;
    }
    sets.push('asignado_a = ?'); params.push(b.asignado_a ? Number(b.asignado_a) : null);
    notas.push('Asignada a ' + nombre);
  }
  if (!sets.length) return { ok: true, cambios: 0 };
  const estado = b.estado && ESTADOS[b.estado] ? b.estado : c.estado;
  tx(() => {
    q(`UPDATE casos SET ${sets.join(', ')}, actualizado = ? WHERE id = ?`).run(...params, nowIso(), c.id);
    addEvento(c.id, estado, notas.join('. '), true, u.id);
  });
  return { ok: true, cambios: sets.length };
});

route('POST', '/api/casos/([A-Z0-9-]+)/respuesta', async (req, _res, _url, m) => {
  const u = requireUser(req);
  const c = getCaso(m[1], u);
  const b = await readJson(req, 200 * 1024);
  const texto = clean(b.texto, 5000);
  if (texto.length < 10) throw new HttpError(400, 'La respuesta necesita al menos 10 caracteres.');
  tx(() => {
    q('UPDATE casos SET respuesta = ?, estado = ?, respondido_en = ?, actualizado = ? WHERE id = ?')
      .run(texto, 'respondido', todayStr(), nowIso(), c.id);
    addEvento(c.id, 'respondido', 'Respuesta registrada', true, u.id);
  });
  return { ok: true };
});

route('POST', '/api/casos/([A-Z0-9-]+)/nota', async (req, _res, _url, m) => {
  const u = requireUser(req);
  const c = getCaso(m[1], u);
  const b = await readJson(req);
  const texto = clean(b.texto, 1000);
  if (!texto) throw new HttpError(400, 'Escriba la nota.');
  addEvento(c.id, c.estado, texto, false, u.id);
  q('UPDATE casos SET actualizado = ? WHERE id = ?').run(nowIso(), c.id);
  return { ok: true };
});

route('GET', '/api/adjuntos/(\\d+)', async (req, res, _url, m) => {
  const u = requireUser(req);
  const v = visibleClause(u);
  const a = q(`SELECT a.* FROM adjuntos a JOIN casos c ON c.id = a.caso_id WHERE a.id = ? AND ${v.sql}`).get(Number(m[1]), ...v.params);
  if (!a) throw new HttpError(404, 'Archivo no encontrado.');
  const file = path.join(UPLOAD_DIR, path.basename(a.archivo));
  if (!fs.existsSync(file)) throw new HttpError(404, 'Archivo no encontrado.');
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': a.tam,
    'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(a.nombre)}`,
    'X-Content-Type-Options': 'nosniff',
  });
  fs.createReadStream(file).pipe(res);
  return undefined;
});

route('GET', '/api/export.csv', async (req, res) => {
  const u = requireUser(req);
  const v = visibleClause(u);
  const rows = q(`SELECT c.*, us.nombre AS asignado_nombre FROM casos c LEFT JOIN usuarios us ON us.id = c.asignado_a
                  WHERE ${v.sql} ORDER BY c.id`).all(...v.params);
  const head = ['radicado', 'tipo', 'asunto', 'dependencia', 'estado', 'radicada_el', 'vence_el', 'respondida_el', 'asignada_a', 'solicitante'];
  const lines = rows.map((c) => [c.radicado, TIPOS[c.tipo]?.nombre || c.tipo, c.asunto, c.dependencia, ESTADOS[c.estado],
    c.fecha, c.vence, c.respondido_en || '', c.asignado_nombre || '', c.nombre || 'Anónimo'].map(csvCell).join(','));
  const csv = '﻿' + [head.join(',')].concat(lines).join('\r\n');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="pqrs-${todayStr()}.csv"`,
    'Cache-Control': 'no-store',
  });
  res.end(csv);
  return undefined;
});

// Administración
route('GET', '/api/admin/usuarios', async (req) => {
  requireAdmin(req);
  return { usuarios: q('SELECT id, nombre, email, rol, dependencia, activo, creado FROM usuarios ORDER BY nombre').all() };
});
route('POST', '/api/admin/usuarios', async (req) => {
  requireAdmin(req);
  const b = await readJson(req);
  const nombre = clean(b.nombre, 80);
  const email = clean(b.email, 120).toLowerCase();
  const password = String(b.password || '');
  const rol = b.rol === 'admin' ? 'admin' : 'funcionario';
  const dep = clean(b.dependencia, 80);
  if (!nombre) throw new HttpError(400, 'Escriba el nombre.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'El correo no es válido.');
  if (password.length < 10) throw new HttpError(400, 'La contraseña necesita al menos 10 caracteres.');
  if (dep && !dependencias().includes(dep)) throw new HttpError(400, 'Dependencia no válida.');
  if (q('SELECT 1 FROM usuarios WHERE email = ?').get(email)) throw new HttpError(409, 'Ya existe un usuario con ese correo.');
  q('INSERT INTO usuarios (nombre, email, pass_hash, rol, dependencia, creado) VALUES (?,?,?,?,?,?)')
    .run(nombre, email, hashSecret(password), rol, dep, nowIso());
  return { ok: true };
});
route('PATCH', '/api/admin/usuarios/(\\d+)', async (req, _res, _url, m) => {
  const me = requireAdmin(req);
  const id = Number(m[1]);
  const t = q('SELECT * FROM usuarios WHERE id = ?').get(id);
  if (!t) throw new HttpError(404, 'Usuario no encontrado.');
  const b = await readJson(req);
  const nombre = b.nombre !== undefined ? clean(b.nombre, 80) : t.nombre;
  const rol = b.rol !== undefined ? (b.rol === 'admin' ? 'admin' : 'funcionario') : t.rol;
  const dep = b.dependencia !== undefined ? clean(b.dependencia, 80) : t.dependencia;
  const activo = b.activo !== undefined ? (b.activo ? 1 : 0) : t.activo;
  if (!nombre) throw new HttpError(400, 'Escriba el nombre.');
  if (dep && !dependencias().includes(dep)) throw new HttpError(400, 'Dependencia no válida.');
  const quedaAdmin = rol === 'admin' && activo === 1;
  if (t.rol === 'admin' && t.activo === 1 && !quedaAdmin) {
    const otros = q("SELECT COUNT(*) AS n FROM usuarios WHERE rol = 'admin' AND activo = 1 AND id <> ?").get(id).n;
    if (otros === 0) throw new HttpError(400, 'Debe quedar al menos un administrador activo.');
  }
  let pass = t.pass_hash;
  if (b.password) {
    if (String(b.password).length < 10) throw new HttpError(400, 'La contraseña necesita al menos 10 caracteres.');
    pass = hashSecret(String(b.password));
  }
  q('UPDATE usuarios SET nombre = ?, rol = ?, dependencia = ?, activo = ?, pass_hash = ? WHERE id = ?').run(nombre, rol, dep, activo, pass, id);
  if (!activo || b.password) q('DELETE FROM sesiones WHERE usuario_id = ? AND ? <> usuario_id').run(id, me.id);
  return { ok: true };
});
route('PUT', '/api/admin/config', async (req) => {
  requireAdmin(req);
  const b = await readJson(req);
  const nombre = clean(b.entidad, 80);
  if (!nombre) throw new HttpError(400, 'Escriba el nombre de la entidad.');
  const deps = [...new Set((Array.isArray(b.dependencias) ? b.dependencias : []).map((d) => clean(d, 80)).filter(Boolean))];
  if (!deps.length) throw new HttpError(400, 'Debe haber al menos una dependencia.');
  setConfig('entidad', nombre);
  setConfig('dependencias', deps);
  return { ok: true };
});

// ---------- Servidor ----------
const server = http.createServer(async (req, res) => {
  const secure = isSecure(req);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'");
  if (secure) res.setHeader('Strict-Transport-Security', 'max-age=15552000');

  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.headers['x-requested-with'] !== 'pqrs') throw new HttpError(403, 'Solicitud no permitida.');
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = r.re.exec(url.pathname);
        if (!m) continue;
        const out = await r.handler(req, res, url, m);
        if (out !== undefined && !res.headersSent) sendJson(res, 200, out);
        return;
      }
      throw new HttpError(404, 'Ruta no encontrada.');
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Método no permitido.');
    if (!serveStatic(PUBLIC_DIR, url.pathname, res)) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('No encontrado');
    }
  } catch (e) {
    if (res.headersSent) { res.end(); return; }
    if (e instanceof HttpError) return sendJson(res, e.status, { error: e.message });
    console.error(e);
    sendJson(res, 500, { error: 'Ocurrió un error inesperado. Intente de nuevo.' });
  }
});

bootstrapAdmin();
server.listen(PORT, () => console.log(`Atención ciudadana lista en http://localhost:${PORT}`));

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { server.close(() => { try { db.close(); } catch {} process.exit(0); }); });
}
