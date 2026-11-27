'use strict';

/**
 * Regression tests for the default-deny tool registry (issue #5).
 *
 * SECURITY.md states the design assumption: "Tools are default-deny. An
 * unregistered tool cannot run." The existing coverage in
 * test/tools.test.js only pins this for an *empty* registry with an empty
 * allowlist. These tests pin the failure mode that actually matters in
 * production: the shipped default registry must refuse a tool it never
 * registered — even when a task's `allowedTools` names that tool. An
 * allowlist is a permission to run a registered tool, not a way to conjure
 * one into existence (e.g. a prompt-injected or misconfigured task asking
 * for `shell.exec` must still be refused, before any side effect).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  ToolRegistry, ToolDeniedError, ToolNotFoundError,
  buildDefaultRegistry,
} = require('../aegis/tools/registry');

function tmpAuditSink() {
  const events = [];
  return { events, audit: { append: (e) => events.push(e) } };
}

test('default-deny: an unregistered tool is refused even when the task allowlists it', async () => {
  const r = buildDefaultRegistry();
  const sink = tmpAuditSink();
  // `shell.exec` is not a shipped tool; naming it in allowedTools must not
  // let it run — the registry checks registration before the allowlist.
  await assert.rejects(
    () => r.run('shell.exec', { command: 'id' }, { allowedTools: ['shell.exec'], audit: sink.audit }),
    (err) => err instanceof ToolNotFoundError && err.code === 'TOOL_NOT_FOUND',
  );
  assert.ok(sink.events.find((e) => e.kind === 'tool.deny' && e.reason === 'not_registered'));
});

test('default-deny: an unregistered tool is refused with no context at all', async () => {
  const r = buildDefaultRegistry();
  await assert.rejects(
    () => r.run('shell.exec', { command: 'id' }),
    (err) => err instanceof ToolNotFoundError && err.code === 'TOOL_NOT_FOUND',
  );
});

test('default-deny: the shipped registry genuinely has no such tool', () => {
  const r = buildDefaultRegistry();
  assert.equal(r.get('shell.exec'), null);
  assert.ok(!r.list().includes('shell.exec'));
});

test('default-deny: unregistered and not-allowed fail differently', async () => {
  const r = buildDefaultRegistry();
  // A registered tool that is not on the task allowlist is denied, not
  // "not found" — the two failure modes stay distinct so callers (and the
  // audit trail) can tell a missing tool from a missing permission.
  await assert.rejects(
    () => r.run('hash.sha256', { value: 'x' }, { allowedTools: ['echo'] }),
    (err) => err instanceof ToolDeniedError && err.code === 'TOOL_DENIED',
  );
  await assert.rejects(
    () => r.run('shell.exec', {}, { allowedTools: ['shell.exec'] }),
    (err) => err instanceof ToolNotFoundError && err.code === 'TOOL_NOT_FOUND',
  );
});
