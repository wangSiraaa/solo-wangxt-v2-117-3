'use strict';

const db = require('./db');

// Resolve (token -> session) and (user, doc -> active role). Every call
// hits the database: we do not cache authorization across updates, so a
// revoked member loses write access immediately, and a client claiming a
// room id it does not belong to is rejected with that exact id.

async function resolveToken(token) {
  if (!token || typeof token !== 'string') return null;
  const { rows } = await db.query(
    `SELECT u.id AS user_id, u.tenant_id, u.name
       FROM users u
      WHERE u.id = $1`,
    [token],
  );
  return rows[0] || null;
}

async function getActiveRole(userId, docId) {
  const { rows } = await db.query(
    `SELECT m.role, d.tenant_id, d.title
       FROM document_members m
       JOIN documents d ON d.id = m.doc_id
       JOIN users u ON u.id = m.user_id
      WHERE m.doc_id = $1
        AND m.user_id = $2
        AND m.revoked_at IS NULL
        AND u.tenant_id = d.tenant_id`,
    [docId, userId],
  );
  return rows[0] || null;
}

async function listActiveDocs(userId) {
  const { rows } = await db.query(
    `SELECT m.doc_id, m.role
       FROM document_members m
       JOIN documents d ON d.id = m.doc_id
       JOIN users u ON u.id = m.user_id
      WHERE m.user_id = $1
        AND m.revoked_at IS NULL
        AND u.tenant_id = d.tenant_id`,
    [userId],
  );
  return rows;
}

// Look up a user by id (invite target validation).
async function findUser(userId) {
  if (!userId || typeof userId !== 'string') return null;
  const { rows } = await db.query(
    `SELECT id AS user_id, tenant_id, name FROM users WHERE id = $1`,
    [userId],
  );
  return rows[0] || null;
}

// --- Member management (owner-only HTTP API) ------------------------------
// Every mutation stamps changed_at/changed_by so the member list can show
// who last touched a membership and when. Writes go through the same
// per-statement pool client as the read path; authorization is re-evaluated
// by the caller on every request, never cached.

// All memberships of a doc, including revoked ones (for the owner list view).
async function listMembers(docId) {
  const { rows } = await db.query(
    `SELECT m.user_id, u.name, u.tenant_id, m.role,
            m.granted_at, m.changed_at, m.changed_by, m.revoked_at
       FROM document_members m
       JOIN users u ON u.id = m.user_id
      WHERE m.doc_id = $1
      ORDER BY m.granted_at ASC, m.user_id ASC`,
    [docId],
  );
  return rows;
}

// One membership row regardless of revoked state (null if never a member).
async function getMember(docId, userId) {
  const { rows } = await db.query(
    `SELECT m.user_id, m.role, m.granted_at, m.changed_at, m.changed_by,
            m.revoked_at
       FROM document_members m
      WHERE m.doc_id = $1 AND m.user_id = $2`,
    [docId, userId],
  );
  return rows[0] || null;
}

// Invite: insert a fresh membership, or revive a previously revoked one
// (granted_at keeps the original grant time; changed_* tracks the re-invite).
async function inviteMember(docId, userId, role, changedBy) {
  const { rows } = await db.query(
    `INSERT INTO document_members (doc_id, user_id, role, changed_by)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (doc_id, user_id) DO UPDATE
       SET role = EXCLUDED.role,
           revoked_at = NULL,
           changed_at = now(),
           changed_by = EXCLUDED.changed_by
     RETURNING user_id, role, granted_at, changed_at, changed_by, revoked_at`,
    [docId, userId, role, changedBy],
  );
  return rows[0];
}

// Change role of an ACTIVE membership. Returns the updated row, or null if
// there is no active membership for (doc, user).
async function setMemberRole(docId, userId, role, changedBy) {
  const { rows } = await db.query(
    `UPDATE document_members
        SET role = $3, changed_at = now(), changed_by = $4
      WHERE doc_id = $1 AND user_id = $2 AND revoked_at IS NULL
      RETURNING user_id, role, granted_at, changed_at, changed_by, revoked_at`,
    [docId, userId, role, changedBy],
  );
  return rows[0] || null;
}

// Revoke an active membership. Returns the updated row, or null if there was
// no active membership to revoke.
async function revokeMember(docId, userId, changedBy = null) {
  const { rows } = await db.query(
    `UPDATE document_members
        SET revoked_at = now(), changed_at = now(), changed_by = $3
      WHERE doc_id = $1 AND user_id = $2 AND revoked_at IS NULL
      RETURNING user_id, role, granted_at, changed_at, changed_by, revoked_at`,
    [docId, userId, changedBy],
  );
  return rows[0] || null;
}

module.exports = {
  resolveToken,
  findUser,
  getActiveRole,
  listActiveDocs,
  listMembers,
  getMember,
  inviteMember,
  setMemberRole,
  revokeMember,
};
