#!/usr/bin/env node
'use strict';

// Demo: owner-driven member management at runtime.
//
//   1. owner lists members of the doc (HTTP, owner-only)
//   2. owner invites Erin (same tenant, no membership yet) as writer
//   3. Erin connects and writes — collaboration works
//   4. owner demotes Erin to reader; her EXISTING connection's next write
//      is rejected READ_ONLY (per-update re-authorization, no cache)
//   5. owner revokes Erin; her old connection's next write is FORBIDDEN
//      and a fresh reconnect is refused at hello
//
// Requires the gateway running (npm start) with seeded data.

const { DocClient } = require('./lib-client');

const BASE = process.env.HTTP_URL || 'http://127.0.0.1:7777';
const WS_URL = process.env.WS_URL || 'ws://127.0.0.1:7777/ws';
const DOC = process.env.DOC_ID || 'doc-demo';
const OWNER = process.env.TOKEN_OWNER || 'user-owner';
const INVITEE = process.env.TOKEN_INVITEE || 'user-erin';

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function api(method, path, token, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-auth-token': token,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, ...json };
}

function showMembers(title, members) {
  console.log(`\n== ${title}`);
  for (const m of members) {
    console.log(
      `   ${m.userId.padEnd(12)} role=${m.role.padEnd(7)} ` +
      `revoked=${m.revoked} changedBy=${m.changedBy || '-'} changedAt=${m.changedAt}`,
    );
  }
}

async function expectWrite(client, label, shouldSucceed) {
  const tag = `[${label}@${new Date().toISOString().slice(11, 19)}] `;
  const u = client.localEdit((t) => t.insert(t.length, `${tag}\n`));
  try {
    const ack = await client.sendUpdate(u, 5000);
    if (!shouldSucceed) {
      throw new Error(`${label}: write unexpectedly succeeded (seq ${ack.seq})`);
    }
    console.log(`   write accepted, seq=${ack.seq}`);
  } catch (e) {
    if (shouldSucceed) throw new Error(`${label}: write rejected: ${e.message}`);
    console.log(`   write rejected as expected: ${e.message}`);
  }
}

async function main() {
  console.log(`member-management demo on ${DOC} (owner=${OWNER}, invitee=${INVITEE})`);

  // 1. owner lists current members.
  const list0 = await api('GET', `/v1/docs/${DOC}/members`, OWNER);
  if (list0.status !== 200) throw new Error(`list failed: ${JSON.stringify(list0)}`);
  showMembers('members before', list0.members);

  // 2. invite the same-tenant user as writer.
  const inv = await api('POST', `/v1/docs/${DOC}/members`, OWNER,
    { userId: INVITEE, role: 'writer' });
  if (inv.status !== 201) throw new Error(`invite failed: ${JSON.stringify(inv)}`);
  console.log(`\n== invited ${INVITEE} as writer (changedBy=${inv.member.changedBy})`);

  // 3. invitee connects and collaborates.
  const c = new DocClient({ url: WS_URL, token: INVITEE, docId: DOC, name: 'invitee', verbose: true });
  await c.connect();
  console.log(`\n== ${INVITEE} connected, role=${c.role}`);
  await expectWrite(c, 'as-writer', true);

  // 4. demote to reader: the SAME connection's next write must be rejected.
  const dem = await api('PATCH', `/v1/docs/${DOC}/members/${INVITEE}`, OWNER,
    { role: 'reader' });
  if (dem.status !== 200) throw new Error(`demote failed: ${JSON.stringify(dem)}`);
  console.log(`\n== demoted ${INVITEE} to reader; old connection writes again:`);
  await expectWrite(c, 'as-reader', false);

  // 5. revoke: old connection write AND a fresh reconnect are both refused.
  const rev = await api('DELETE', `/v1/docs/${DOC}/members/${INVITEE}`, OWNER);
  if (rev.status !== 200) throw new Error(`revoke failed: ${JSON.stringify(rev)}`);
  console.log(`\n== revoked ${INVITEE}; old connection writes again:`);
  await expectWrite(c, 'after-revoke', false);

  console.log(`\n== ${INVITEE} reconnects after revoke:`);
  const c2 = new DocClient({ url: WS_URL, token: INVITEE, docId: DOC, name: 'invitee-2' });
  try {
    await c2.connect();
    throw new Error('reconnect unexpectedly succeeded');
  } catch (e) {
    console.log(`   reconnect refused as expected: ${e.message}`);
  }

  const list1 = await api('GET', `/v1/docs/${DOC}/members`, OWNER);
  showMembers('members after', list1.members);

  c.close();
  await sleep(100);
  console.log('\ndemo done');
  process.exit(0);
}

main().catch((e) => { console.error('demo failed:', e); process.exit(1); });
