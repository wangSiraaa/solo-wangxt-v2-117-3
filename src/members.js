'use strict';

// Runtime membership administration for one document.
//
// All operations are OWNER-only and re-resolved against the database on every
// request (same trust model as the write path: nothing about authorization is
// cached). Cross-tenant users (whether the caller or the invitee) and
// non-owners therefore cannot change any member record.
//
// A membership row is never deleted: revoking sets revoked_at, and a later
// re-invite reactivates the same (doc_id, user_id) row. role/updated_at/
// updated_by record the current state plus who last changed it, so the member
// list can show the current role and the revoked state with audit context.
//
// Owner is intentionally not manageable through this API: there is no owner
// handover, owners can neither be demoted nor revoked, and invites/role
// changes only accept reader/writer.

const db = require('./db');
const { resolveToken, getActiveRole } = require('./permissions');

const MANAGED_ROLES = ['reader', 'writer'];

class MemberError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'MemberError';
    this.code = code;
    this.status = status;
  }
}

function formatMember(row) {
  return {
    userId: row.user_id,
    name: row.name,
    role: row.role,
    active: row.revoked_at == null,
    grantedAt: row.granted_at instanceof Date ? row.granted_at.toISOString() : row.granted_at,
    revokedAt: row.revoked_at instanceof Date ? row.revoked_at.toISOString() : row.revoked_at,
    updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at,
    updatedBy: row.updated_by || null,
  };
}

// Authenticate the bearer token and assert an active owner membership in the
// caller's own tenant. Document existence for a non-member is not revealed.
async function requireOwner(token, docId) {
  const session = await resolveToken(Array.isArray(token) ? token[0] : token);
  if (!session) throw new MemberError('BAD_TOKEN', 'unknown token', 401);
  const membership = await getActiveRole(session.user_id, docId);
  if (!membership || membership.tenant_id !== session.tenant_id) {
    throw new MemberError('FORBIDDEN', 'no access to this document', 403);
  }
  if (membership.role !== 'owner') {
    throw new MemberError('NOT_OWNER', 'only the document owner can manage members', 403);
  }
  return session;
}

// Every member row (including revoked ones) with tenant match enforced in SQL.
async function listMembers(docId, session) {
  const { rows } = await db.query(
    `SELECT m.user_id, u.name, m.role, m.granted_at, m.revoked_at,
            m.updated_at, m.updated_by
       FROM document_members m
       JOIN documents d ON d.id = m.doc_id
       JOIN users u ON u.id = m.user_id
      WHERE m.doc_id = $1
        AND d.tenant_id = $2
        AND u.tenant_id = d.tenant_id
      ORDER BY (m.role = 'owner') DESC,
               (m.revoked_at IS NULL) DESC,
               m.granted_at ASC,
               m.user_id ASC`,
    [docId, session.tenant_id],
  );
  return rows.map(formatMember);
}

async function findUser(userId, tenantId) {
  const { rows } = await db.query(
    `SELECT id, tenant_id, name FROM users WHERE id = $1`,
    [userId],
  );
  const user = rows[0] || null;
  if (!user) throw new MemberError('NO_SUCH_USER', `user not found: ${userId}`, 404);
  if (user.tenant_id !== tenantId) {
    throw new MemberError('CROSS_TENANT', 'invitee belongs to a different tenant', 403);
  }
  return user;
}

// Invite an existing same-tenant user as reader/writer. A previously revoked
// row is reactivated; an already active row is returned unchanged (409).
async function inviteMember(docId, session, userId, role) {
  if (!userId || typeof userId !== 'string') {
    throw new MemberError('BAD_REQUEST', 'userId is required', 400);
  }
  if (!MANAGED_ROLES.includes(role)) {
    throw new MemberError('BAD_ROLE', `role must be one of: ${MANAGED_ROLES.join(', ')}`, 400);
  }
  await findUser(userId, session.tenant_id);

  const client = await db.getClient();
  let reactivated = false;
  try {
    await client.query('BEGIN');
    // Lock the doc row so concurrent invites/role changes serialize.
    const locked = await client.query(
      `SELECT d.tenant_id FROM documents d WHERE d.id = $1 FOR UPDATE`,
      [docId],
    );
    if (locked.rowCount === 0) {
      throw new MemberError('NO_SUCH_DOC', 'document not found', 404);
    }
    if (locked.rows[0].tenant_id !== session.tenant_id) {
      throw new MemberError('FORBIDDEN', 'document belongs to a different tenant', 403);
    }
    const existing = await client.query(
      `SELECT user_id, role, revoked_at
         FROM document_members WHERE doc_id = $1 AND user_id = $2`,
      [docId, userId],
    );
    if (existing.rowCount > 0 && existing.rows[0].revoked_at == null) {
      throw new MemberError('ALREADY_MEMBER',
        `user is already an active ${existing.rows[0].role}`, 409);
    }
    reactivated = existing.rowCount > 0;
    await client.query(
      `INSERT INTO document_members (doc_id, user_id, role, updated_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (doc_id, user_id) DO UPDATE
         SET role = EXCLUDED.role,
             revoked_at = NULL,
             updated_at = now(),
             updated_by = EXCLUDED.updated_by`,
      [docId, userId, role, session.user_id],
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  const member = await getMember(docId, userId);
  return { invited: true, reactivated, member };
}

// Change an active non-owner member between reader/writer. Same role is a
// 409 no-op so audit fields are not stamped with a non-change.
async function setMemberRole(docId, session, userId, role) {
  if (!userId || typeof userId !== 'string') {
    throw new MemberError('BAD_REQUEST', 'userId is required', 400);
  }
  if (!MANAGED_ROLES.includes(role)) {
    throw new MemberError('BAD_ROLE',
      `role must be one of: ${MANAGED_ROLES.join(', ')}`, 400);
  }
  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    const locked = await client.query(
      `SELECT d.tenant_id FROM documents d WHERE d.id = $1 FOR UPDATE`,
      [docId],
    );
    if (locked.rowCount === 0) {
      throw new MemberError('NO_SUCH_DOC', 'document not found', 404);
    }
    if (locked.rows[0].tenant_id !== session.tenant_id) {
      throw new MemberError('FORBIDDEN', 'document belongs to a different tenant', 403);
    }
    const existing = await client.query(
      `SELECT role, revoked_at FROM document_members
        WHERE doc_id = $1 AND user_id = $2`,
      [docId, userId],
    );
    if (existing.rowCount === 0) {
      throw new MemberError('NOT_MEMBER', 'user is not a member; invite first', 404);
    }
    if (existing.rows[0].revoked_at != null) {
      throw new MemberError('MEMBER_REVOKED',
        'membership is revoked; invite the user again to reactivate', 409);
    }
    if (existing.rows[0].role === 'owner') {
      throw new MemberError('OWNER_PROTECTED',
        'the owner role cannot be changed; no owner handover is supported', 409);
    }
    if (existing.rows[0].role === role) {
      throw new MemberError('ROLE_UNCHANGED', `member is already ${role}`, 409);
    }
    const upd = await client.query(
      `UPDATE document_members
          SET role = $3, updated_at = now(), updated_by = $4
        WHERE doc_id = $1 AND user_id = $2 AND revoked_at IS NULL
        RETURNING user_id`,
      [docId, userId, role, session.user_id],
    );
    if (upd.rowCount === 0) throw new MemberError('NOT_MEMBER', 'no active membership', 404);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  return { changed: true, role, member: await getMember(docId, userId) };
}

// Revoke an active non-owner member. The per-update write authorization makes
// the change immediate for existing connections, and a new hello is refused.
async function revokeMemberAdmin(docId, session, userId) {
  if (!userId || typeof userId !== 'string') {
    throw new MemberError('BAD_REQUEST', 'userId is required', 400);
  }
  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    const locked = await client.query(
      `SELECT d.tenant_id FROM documents d WHERE d.id = $1 FOR UPDATE`,
      [docId],
    );
    if (locked.rowCount === 0) {
      throw new MemberError('NO_SUCH_DOC', 'document not found', 404);
    }
    if (locked.rows[0].tenant_id !== session.tenant_id) {
      throw new MemberError('FORBIDDEN', 'document belongs to a different tenant', 403);
    }
    const existing = await client.query(
      `SELECT role, revoked_at FROM document_members
        WHERE doc_id = $1 AND user_id = $2`,
      [docId, userId],
    );
    if (existing.rowCount === 0) {
      throw new MemberError('NOT_MEMBER', 'user is not a member', 404);
    }
    if (existing.rows[0].revoked_at != null) {
      throw new MemberError('ALREADY_REVOKED', 'membership is already revoked', 409);
    }
    if (existing.rows[0].role === 'owner') {
      throw new MemberError('OWNER_PROTECTED', 'the owner cannot be revoked', 409);
    }
    const upd = await client.query(
      `UPDATE document_members
          SET revoked_at = now(), updated_at = now(), updated_by = $3
        WHERE doc_id = $1 AND user_id = $2 AND revoked_at IS NULL
        RETURNING user_id`,
      [docId, userId, session.user_id],
    );
    if (upd.rowCount === 0) throw new MemberError('NOT_MEMBER', 'no active membership', 404);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  return { revoked: true, member: await getMember(docId, userId) };
}

async function getMember(docId, userId) {
  const { rows } = await db.query(
    `SELECT m.user_id, u.name, m.role, m.granted_at, m.revoked_at,
            m.updated_at, m.updated_by
       FROM document_members m
       JOIN users u ON u.id = m.user_id
      WHERE m.doc_id = $1 AND m.user_id = $2`,
    [docId, userId],
  );
  return rows[0] ? formatMember(rows[0]) : null;
}

module.exports = {
  MemberError,
  requireOwner,
  listMembers,
  inviteMember,
  setMemberRole,
  revokeMemberAdmin,
  getMember,
};
