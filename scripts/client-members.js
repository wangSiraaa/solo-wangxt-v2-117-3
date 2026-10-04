#!/usr/bin/env node
'use strict';

// Demo: runtime member management over HTTP + immediate effect on WebSocket
// connections (per-update authorization is re-checked from the database).
//
// Flow (all driven by user-owner against doc-demo):
//   1. owner lists members (seed roles visible)
//   2. owner invites user-erin (same tenant, previously no membership) as writer
//   3. erin connects over WebSocket and writes successfully
//   4. owner demotes erin writer -> reader: the SAME old connection's next
//      write is rejected with READ_ONLY
//   5. owner promotes erin reader -> writer: that same connection's next
//      write succeeds again (role changes apply in both directions)
//   6. owner revokes erin: the old connection's next write gets FORBIDDEN,
//      and a brand-new connection is refused at hello
//   7. non-owners (reader) and cross-tenant users cannot change any record;
//      inviting a cross-tenant user is refused
//   8. final member list shows role / revoked state / updatedAt / updatedBy
//
// Run after `npm run seed:reset` (idempotent enough to re-run: an active
// membership from a previous run is set to the needed role).

const { DocClient } = require('./lib-client');

const WS_URL = process.env.WS_URL || 'ws://127.0.0.1:7777/ws';
const HTTP_BASE = WS_URL.replace(/\/ws$/, '').replace(/^ws(s?):\/\//, 'http$1://');
const DOC = process.env.DOC_ID || 'doc-demo';
const OWNER = process.env.TOKEN_OWNER || 'user-owner';
const TARGET = process.env.TOKEN_TARGET || 'user-erin';

let failures = 0;
function check(label, cond, extra) {
  if (cond) {
    console.log(`  PASS  ${label}`);
  } else {
    failures += 1;
    console.log(`  FAIL  ${label}${extra ? `  ${extra}` : ''}`);
  }
}

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function api(method, path, token, body) {
  const res = await fetch(`${HTTP_BASE}${path}`, {
    method,
    headers: {
      'x-auth-token': token,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* empty error body */ }
  return { status: res.status, json };
}

async function expectWriteDenied(client, label, code, tag) {
  // probeWrite generates the bytes from a throwaway Yjs identity so the
  // refused edit does not land in this client's own local document.
  let err = null;
  try {
    await client.probeWrite(tag, 3000);
  } catch (e) {
    err = e;
  }
  check(`${label} -> ${code}`, !!err && err.code === code,
    err ? `got ${err.code}: ${err.message}` : 'write unexpectedly succeeded');
}

async function main() {
  console.log(`== member-management demo on ${DOC} via ${HTTP_BASE} ==`);

  // 1. Owner sees the seed member list.
  let r = await api('GET', `/v1/docs/${DOC}/members`, OWNER);
  check('owner lists members', r.status === 200, JSON.stringify(r.json));
  console.log('    members:', r.json.members
    .map((m) => `${m.userId}:${m.role}${m.active ? '' : '(revoked)'}`).join(', '));

  // 2. Invite erin as writer (tolerate a previous run's leftover membership).
  r = await api('POST', `/v1/docs/${DOC}/members/invite`, OWNER,
    { userId: TARGET, role: 'writer' });
  if (r.status === 409 && r.json.error === 'ALREADY_MEMBER') {
    r = await api('POST', `/v1/docs/${DOC}/members/${TARGET}/role`, OWNER,
      { role: 'writer' });
    if (r.status === 409 && r.json.error === 'ROLE_UNCHANGED') {
      // already writer: fine
    }
  }
  check('owner invites same-tenant user as writer',
    r.status === 201 || r.status === 200, JSON.stringify(r.json));

  // 3. Erin connects on a fresh WebSocket and collaborates.
  const erin = new DocClient({ url: WS_URL, token: TARGET, docId: DOC, name: 'erin' });
  await erin.connect();
  check('invited writer connects, hello role=writer', erin.role === 'writer',
    `role=${erin.role}`);
  erin.localEdit((t) => t.insert(t.length, `[hello from ${TARGET}] `));
  await erin.flush();
  check('invited writer sends an update (ack ok)', erin.acks >= 1);

  // 4. Demote to reader: the OLD connection's next write must be refused.
  r = await api('POST', `/v1/docs/${DOC}/members/${TARGET}/role`, OWNER,
    { role: 'reader' });
  check('owner changes role writer -> reader',
    r.status === 200 && r.json.changed === true && r.json.member.role === 'reader',
    JSON.stringify(r.json));
  check('role change stamped updated_by=owner',
    r.json.member.updatedBy === OWNER && !!r.json.member.updatedAt,
    JSON.stringify(r.json.member));
  await expectWriteDenied(erin, 'old connection write after demotion', 'READ_ONLY',
    'erin-as-reader');

  // 5. Promote back to writer: same old connection writes immediately again.
  r = await api('POST', `/v1/docs/${DOC}/members/${TARGET}/role`, OWNER,
    { role: 'writer' });
  check('owner changes role reader -> writer', r.status === 200,
    JSON.stringify(r.json));
  erin.localEdit((t) => t.insert(t.length, `[writer again] `));
  await erin.flush();
  check('old connection writes successfully after re-promotion', erin.acks >= 2);

  // 6. Revoke: old connection write denied, fresh connection refused.
  r = await api('DELETE', `/v1/docs/${DOC}/members/${TARGET}`, OWNER);
  check('owner revokes member',
    r.status === 200 && r.json.revoked === true &&
      r.json.member.active === false && !!r.json.member.revokedAt,
    JSON.stringify(r.json));
  await expectWriteDenied(erin, 'old connection write after revocation', 'FORBIDDEN',
    'erin-revoked');

  erin.close();
  await sleep(100);
  const erin2 = new DocClient({ url: WS_URL, token: TARGET, docId: DOC, name: 'erin2' });
  let helloErr = null;
  try {
    await erin2.connect();
  } catch (e) {
    helloErr = e;
  }
  check('revoked user cannot open a new connection',
    !!helloErr && helloErr.code === 'FORBIDDEN',
    helloErr ? `${helloErr.code}: ${helloErr.message}` : 'hello unexpectedly succeeded');
  try { erin2.hardClose(); } catch { /* never connected */ }

  // 7. Authorization of the management surface itself.
  r = await api('GET', `/v1/docs/${DOC}/members`, 'user-carol');
  check('reader cannot list members (403)', r.status === 403, JSON.stringify(r.json));

  r = await api('POST', `/v1/docs/${DOC}/members/invite`, 'user-carol',
    { userId: 'user-bob', role: 'writer' });
  check('reader cannot invite (403)', r.status === 403, JSON.stringify(r.json));

  r = await api('POST', `/v1/docs/${DOC}/members/user-bob/role`, 'user-alice',
    { role: 'reader' });
  check('non-owner writer cannot change roles (403)', r.status === 403,
    JSON.stringify(r.json));

  // Dave is a valid user but in tenant-globex: he has no membership in this
  // ACME doc, so management calls are refused and change nothing.
  r = await api('POST', `/v1/docs/${DOC}/members/invite`, 'user-dave',
    { userId: 'user-bob', role: 'reader' });
  check('cross-tenant user cannot invite (403)', r.status === 403,
    JSON.stringify(r.json));
  r = await api('DELETE', `/v1/docs/${DOC}/members/user-bob`, 'user-dave');
  check('cross-tenant user cannot revoke (403)', r.status === 403,
    JSON.stringify(r.json));

  // An owner cannot pull a foreign-tenant user into the document either.
  r = await api('POST', `/v1/docs/${DOC}/members/invite`, OWNER,
    { userId: 'user-dave', role: 'writer' });
  check('owner cannot invite cross-tenant user (403 CROSS_TENANT)',
    r.status === 403 && r.json.error === 'CROSS_TENANT', JSON.stringify(r.json));

  // Bad role values are rejected and leave no record.
  r = await api('POST', `/v1/docs/${DOC}/members/invite`, OWNER,
    { userId: TARGET, role: 'owner' });
  check('invite with role=owner is rejected (no owner handover)',
    r.status === 400 && r.json.error === 'BAD_ROLE', JSON.stringify(r.json));

  // 8. Final list shows current role and revoked state with audit fields.
  r = await api('GET', `/v1/docs/${DOC}/members`, OWNER);
  const target = r.json.members.find((m) => m.userId === TARGET);
  check('list shows revoked target with role/revokedAt/updatedAt/updatedBy',
    !!target && target.active === false && target.role === 'writer' &&
      !!target.revokedAt && !!target.updatedAt && target.updatedBy === OWNER,
    JSON.stringify(target));
  const bob = r.json.members.find((m) => m.userId === 'user-bob');
  check('cross-tenant/non-owner attempts did not mutate other records',
    !!bob && bob.active === true && bob.role === 'writer', JSON.stringify(bob));

  console.log(failures === 0
    ? '\nall member-management checks passed'
    : `\n${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('demo failed:', e); process.exit(1); });
