'use strict';

/**
 * Regression tests for the default-deny tool registry policy.
 *
 * SECURITY.md states: "Tools are default-deny. An unregistered tool cannot run."
 * These tests pin that boundary across empty registries, the default registry,
 * explicit task allowlists, and prototype-property tool names.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { Audit } = require('../aegis/audit');
const {
  ToolRegistry,
  ToolNotFoundError,
  buildDefaultRegistry,
} = require('../aegis/tools/registry');

function tmpAuditSink() {
  const events = [];
  return { events, audit: { append: (e) => events.push(e) } };
}

test('default-deny: empty registry refuses an unregistered tool even when allowlisted', async () => {
  const registry = new ToolRegistry();
  const sink = tmpAuditSink();

  await assert.rejects(
    () => registry.run('unregistered.tool', { cmd: 'id' }, {
      allowedTools: ['unregistered.tool'],
      maxRiskLevel: 'destructive',
      audit: sink.audit,
    }),
    (err) => err instanceof ToolNotFoundError && err.code === 'TOOL_NOT_FOUND',
  );

  assert.equal(registry.get('unregistered.tool'), null);
  assert.deepEqual(registry.list(), []);
  assert.equal(sink.events.length, 1);
  assert.deepEqual(sink.events[0], {
    kind: 'tool.deny',
    name: 'unregistered.tool',
    reason: 'not_registered',
  });
});

test('default-deny: default registry refuses unregistered tools regardless of allowlist or risk ceiling', async () => {
  const registry = buildDefaultRegistry();
  const sink = tmpAuditSink();

  for (const name of ['shell.exec', 'fs.write', 'http.external', 'unknown.tool']) {
    await assert.rejects(
      () => registry.run(name, {}, {
        allowedTools: [name, 'echo'],
        maxRiskLevel: 'destructive',
        audit: sink.audit,
      }),
      (err) => err instanceof ToolNotFoundError && err.code === 'TOOL_NOT_FOUND',
    );
  }

  assert.equal(sink.events.length, 4);
  for (const ev of sink.events) {
    assert.equal(ev.kind, 'tool.deny');
    assert.equal(ev.reason, 'not_registered');
  }
});

test('default-deny: prototype-like and empty tool names are refused as unregistered', async () => {
  const registry = buildDefaultRegistry();
  const badNames = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', '', undefined];

  for (const name of badNames) {
    const sink = tmpAuditSink();
    await assert.rejects(
      () => registry.run(name, {}, {
        allowedTools: [name],
        audit: sink.audit,
      }),
      (err) => err instanceof ToolNotFoundError && err.code === 'TOOL_NOT_FOUND',
    );
    assert.equal(sink.events.length, 1);
    assert.equal(sink.events[0].kind, 'tool.deny');
    assert.equal(sink.events[0].reason, 'not_registered');
  }
});

test('default-deny: refusal of an unregistered tool is recorded in the HMAC-chained audit log', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-default-deny-'));
  const logPath = path.join(dir, 'audit.log');
  const audit = new Audit(logPath, { key: 'test-audit-key' });
  try {
    const registry = buildDefaultRegistry();
    await assert.rejects(
      () => registry.run('missing.tool', {}, { allowedTools: ['missing.tool'], audit }),
      (err) => err instanceof ToolNotFoundError && err.code === 'TOOL_NOT_FOUND',
    );

    const verification = audit.verify();
    assert.equal(verification.ok, true);
    const records = audit.read();
    assert.equal(records.length, 1);
    assert.deepEqual(records[0].event, {
      kind: 'tool.deny',
      name: 'missing.tool',
      reason: 'not_registered',
    });
  } finally {
    audit.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
