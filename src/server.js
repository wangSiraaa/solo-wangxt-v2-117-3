'use strict';

const Fastify = require('fastify');
const websocket = require('@fastify/websocket');
const config = require('./config');
const db = require('./db');
const { wsConnection } = require('./ws');
const { getRoom } = require('./room');
const { compact, recoverFromStore } = require('./compaction');
const { resolveToken, getActiveRole } = require('./permissions');
const members = require('./members');
const yutil = require('./yutil');

function reqLog(err) {
  console.error('[member-route] internal error:',
    err && err.stack ? err.stack : err);
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

  // --- Membership administration (owner-only) ---------------------------
  // Every route re-authenticates the bearer token and requires an active
  // owner membership in the caller's tenant. The write path keeps checking
  // membership on every update, so these changes take effect on the next
  // write of an existing connection without reconnecting.
  async function memberRoute(reply, fn) {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof members.MemberError) {
        return reply.code(err.status).send({ error: err.code, message: err.message });
      }
      reqLog(err);
      return reply.code(500).send({ error: 'INTERNAL', message: 'internal error' });
    }
  }

  app.get('/v1/docs/:docId/members', async (req, reply) => {
    return memberRoute(reply, async () => {
      const session = await members.requireOwner(
        req.headers['x-auth-token'], req.params.docId);
      const list = await members.listMembers(req.params.docId, session);
      return { docId: req.params.docId, members: list };
    });
  });

  app.post('/v1/docs/:docId/members/invite', async (req, reply) => {
    return memberRoute(reply, async () => {
      const session = await members.requireOwner(
        req.headers['x-auth-token'], req.params.docId);
      const body = req.body || {};
      const out = await members.inviteMember(
        req.params.docId, session, body.userId, body.role);
      return reply.code(201).send({ docId: req.params.docId, ...out });
    });
  });

  app.post('/v1/docs/:docId/members/:userId/role', async (req, reply) => {
    return memberRoute(reply, async () => {
      const session = await members.requireOwner(
        req.headers['x-auth-token'], req.params.docId);
      const body = req.body || {};
      const out = await members.setMemberRole(
        req.params.docId, session, req.params.userId, body.role);
      return { docId: req.params.docId, ...out };
    });
  });

  app.delete('/v1/docs/:docId/members/:userId', async (req, reply) => {
    return memberRoute(reply, async () => {
      const session = await members.requireOwner(
        req.headers['x-auth-token'], req.params.docId);
      const out = await members.revokeMemberAdmin(
        req.params.docId, session, req.params.userId);
      return { docId: req.params.docId, ...out };
    });
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
