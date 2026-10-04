'use strict';

const Fastify = require('fastify');
const websocket = require('@fastify/websocket');
const config = require('./config');
const db = require('./db');
const { wsConnection } = require('./ws');
const { getRoom } = require('./room');
const { compact, recoverFromStore } = require('./compaction');
const { resolveToken, getActiveRole, findUser, listMembers, getMember,
  inviteMember, setMemberRole, revokeMember } = require('./permissions');
const yutil = require('./yutil');

// Member-management endpoints are owner-only. The caller's membership is
// re-resolved against the database on EVERY request (same discipline as the
// per-update write path): a demoted/revoked owner loses management rights on
// the very next call. Only reader/writer roles are assignable here —
// ownership transfer is intentionally out of scope.
const ASSIGNABLE_ROLES = new Set(['reader', 'writer']);

async function requireOwner(req, reply) {
  const token = req.headers['x-auth-token'];
  const session = await resolveToken(Array.isArray(token) ? token[0] : token);
  if (!session) {
    reply.code(401).send({ error: 'BAD_TOKEN' });
    return null;
  }
  const role = await getActiveRole(session.user_id, req.params.docId);
  if (!role || role.tenant_id !== session.tenant_id) {
    reply.code(403).send({ error: 'FORBIDDEN' });
    return null;
  }
  if (role.role !== 'owner') {
    reply.code(403).send({ error: 'NOT_OWNER', message: 'owner role required' });
    return null;
  }
  return { session, membership: role };
}

function memberView(m) {
  return {
    userId: m.user_id,
    name: m.name,
    role: m.role,
    grantedAt: m.granted_at,
    changedAt: m.changed_at,
    changedBy: m.changed_by,
    revoked: m.revoked_at != null,
    revokedAt: m.revoked_at || null,
  };
}

async function memberRoutes(app) {
  // List all memberships of the doc, including revoked ones.
  app.get('/v1/docs/:docId/members', async (req, reply) => {
    if (!(await requireOwner(req, reply))) return;
    const members = await listMembers(req.params.docId);
    return { docId: req.params.docId, members: members.map(memberView) };
  });

  // Invite a same-tenant user as reader/writer. Re-inviting a previously
  // revoked user revives the membership with the new role.
  app.post('/v1/docs/:docId/members', async (req, reply) => {
    const auth = await requireOwner(req, reply);
    if (!auth) return;
    const { userId, role } = req.body || {};
    if (!ASSIGNABLE_ROLES.has(role)) {
      return reply.code(400).send({ error: 'BAD_ROLE', message: 'role must be reader or writer' });
    }
    const target = await findUser(userId);
    if (!target) {
      return reply.code(404).send({ error: 'USER_NOT_FOUND' });
    }
    if (target.tenant_id !== auth.membership.tenant_id) {
      return reply.code(403).send({ error: 'TENANT_MISMATCH', message: 'user belongs to another tenant' });
    }
    const existing = await getMember(req.params.docId, userId);
    if (existing && !existing.revoked_at) {
      return reply.code(409).send({ error: 'ALREADY_MEMBER', message: 'use PATCH to change role' });
    }
    const member = await inviteMember(req.params.docId, userId, role, auth.session.user_id);
    return reply.code(201).send({ ok: true, member: memberView(member) });
  });

  // Change an active member's role (reader <-> writer). Owner memberships
  // cannot be demoted through this API (no ownership transfer).
  app.patch('/v1/docs/:docId/members/:userId', async (req, reply) => {
    const auth = await requireOwner(req, reply);
    if (!auth) return;
    const { role } = req.body || {};
    if (!ASSIGNABLE_ROLES.has(role)) {
      return reply.code(400).send({ error: 'BAD_ROLE', message: 'role must be reader or writer' });
    }
    const existing = await getMember(req.params.docId, req.params.userId);
    if (!existing || existing.revoked_at) {
      return reply.code(404).send({ error: 'NOT_MEMBER' });
    }
    if (existing.role === 'owner') {
      return reply.code(409).send({ error: 'OWNER_LOCKED', message: 'cannot change owner role' });
    }
    const member = await setMemberRole(req.params.docId, req.params.userId, role, auth.session.user_id);
    return { ok: true, member: memberView(member) };
  });

  // Revoke a membership. Takes effect on the target's next frame because
  // the write path re-checks the database per update. Owner memberships
  // cannot be revoked through this API.
  app.delete('/v1/docs/:docId/members/:userId', async (req, reply) => {
    const auth = await requireOwner(req, reply);
    if (!auth) return;
    const existing = await getMember(req.params.docId, req.params.userId);
    if (!existing || existing.revoked_at) {
      return reply.code(404).send({ error: 'NOT_MEMBER' });
    }
    if (existing.role === 'owner') {
      return reply.code(409).send({ error: 'OWNER_LOCKED', message: 'cannot revoke owner' });
    }
    const member = await revokeMember(req.params.docId, req.params.userId, auth.session.user_id);
    return { ok: true, member: memberView(member) };
  });
}

async function buildServer() {
  const app = Fastify({ logger: { level: process.env.LOG_LEVEL || 'info' } });
  await app.register(websocket, {
    options: { maxPayload: 8 * 1024 * 1024 },
  });

  app.get('/healthz', async () => {
    const r = await db.query('SELECT 1 AS ok');
    return { ok: true, db: r.rows[0].ok === 1 };
  });

  // Administrative compaction trigger. Authenticated by user token; the
  // doc must belong to the same tenant and the user must be a writer/owner.
  app.post('/v1/docs/:docId/compact', async (req, reply) => {
    const token = req.headers['x-auth-token'];
    const session = await resolveToken(Array.isArray(token) ? token[0] : token);
    if (!session) return reply.code(401).send({ error: 'BAD_TOKEN' });
    const role = await getActiveRole(session.user_id, req.params.docId);
    if (!role || role.tenant_id !== session.tenant_id) {
      return reply.code(403).send({ error: 'FORBIDDEN' });
    }
    if (role.role === 'reader') return reply.code(403).send({ error: 'READ_ONLY' });

    const room = await getRoom(req.params.docId);
    const out = await compact(room, {
      deleteFolded: !!req.body?.deleteFolded,
      minUpdates: req.body?.minUpdates || 1,
    });
    return out;
  });

  // Recovery probe: rebuild the document purely from PostgreSQL
  // (latest snapshot + surviving tail), return the structural hash.
  app.get('/v1/docs/:docId/recovered-state', async (req, reply) => {
    const token = req.headers['x-auth-token'];
    const session = await resolveToken(Array.isArray(token) ? token[0] : token);
    if (!session) return reply.code(401).send({ error: 'BAD_TOKEN' });
    const role = await getActiveRole(session.user_id, req.params.docId);
    if (!role || role.tenant_id !== session.tenant_id) {
      return reply.code(403).send({ error: 'FORBIDDEN' });
    }
    const doc = await recoverFromStore(req.params.docId);
    const state = yutil.encodeState(doc);
    return {
      docId: req.params.docId,
      stateHash: yutil.sha256(state),
      stateLen: state.length,
      sv: yutil.decodeStateVector(yutil.stateVector(doc)),
      text: doc.getText('content').toString(),
    };
  });

  app.register(async (instance) => {
    instance.get('/ws', { websocket: true }, (socket, req) => {
      wsConnection(socket, req);
    });
  });

  await memberRoutes(app);

  return app;
}

if (require.main === module) {
  buildServer().then(async (app) => {
    await app.listen({ host: config.http.host, port: config.http.port });
    app.log.info(`collab gateway listening on ws://${config.http.host}:${config.http.port}/ws`);

    const shutdown = async (signal) => {
      app.log.info(`received ${signal}, draining...`);
      try {
        await app.close();
        await db.close();
      } finally {
        process.exit(0);
      }
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }).catch((err) => {
    console.error('failed to start gateway:', err);
    process.exit(1);
  });
}

module.exports = { buildServer };
