// SDK tests: wrapFetch against stub fetches returning Anthropic tool_use and
// OpenAI tool_calls bodies, SSE tee reconstruction, record() linkage, block
// mode, and end-to-end verify of the resulting ledger.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { generateKey } from '../src/keys.ts';
import { readEntries } from '../src/ledger.ts';
import { Attestor, extractToolCalls } from '../src/sdk.ts';
import { verifyLedger } from '../src/verify.ts';
import { tmp } from './helpers.ts';

const ANTHROPIC_BODY = JSON.stringify({
  id: 'msg_01',
  type: 'message',
  role: 'assistant',
  model: 'claude-fable-5',
  stop_reason: 'tool_use',
  content: [
    { type: 'text', text: 'Transferring now.' },
    { type: 'tool_use', id: 'toolu_9xy', name: 'payments_transfer', input: { amount: '100.00', to: 'acct-9' } },
  ],
});

const OPENAI_CHAT_BODY = JSON.stringify({
  id: 'chatcmpl-1',
  choices: [
    {
      message: {
        role: 'assistant',
        tool_calls: [
          { id: 'call_ab1', type: 'function', function: { name: 'get_weather', arguments: '{"city":"Berlin"}' } },
        ],
      },
    },
  ],
});

const OPENAI_RESPONSES_BODY = JSON.stringify({
  id: 'resp_1',
  output: [{ type: 'function_call', call_id: 'call_r7', name: 'lookup_order', arguments: '{"order_id":42}' }],
});

function stubFetch(body: string, headers: Record<string, string> = { 'content-type': 'application/json' }) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return new Response(body, { status: 200, headers });
  }) as typeof fetch;
  return { fetch: f, calls };
}

function newAttestor(dir = tmp()) {
  const keys = generateKey(join(dir, 'home'));
  const attestor = new Attestor({ ledger: join(dir, 'ledger'), keys, offline: true });
  return { dir, attestor, ledgerPath: join(dir, 'ledger', 'ledger.jsonl') };
}

test('extractToolCalls: Anthropic tool_use, OpenAI chat + responses', () => {
  const a = extractToolCalls(ANTHROPIC_BODY);
  assert.deepEqual(a, [{ id: 'toolu_9xy', name: 'payments_transfer', input: { amount: '100.00', to: 'acct-9' } }]);
  const c = extractToolCalls(OPENAI_CHAT_BODY);
  assert.deepEqual(c, [{ id: 'call_ab1', name: 'get_weather', input: { city: 'Berlin' } }]);
  const r = extractToolCalls(OPENAI_RESPONSES_BODY);
  assert.deepEqual(r, [{ id: 'call_r7', name: 'lookup_order', input: { order_id: 42 } }]);
});

test('wrapFetch records round trip, app sees identical body, ledger verifies', async () => {
  const { dir, attestor, ledgerPath } = newAttestor();
  const stub = stubFetch(ANTHROPIC_BODY);
  const wrapped = attestor.wrapFetch(stub.fetch);

  const res = await wrapped('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    body: JSON.stringify({ model: 'claude-fable-5', messages: [] }),
  });
  const appBody = await res.text();
  assert.equal(appBody, ANTHROPIC_BODY, 'app-visible body untouched');
  await attestor.close();

  const entries = readEntries(ledgerPath);
  const req = entries.find((e) => e.type === 'call_request')!;
  assert.equal(req.origin, 'sdk');
  assert.equal(req.tool?.server, 'api.anthropic.com');
  assert.ok(req.payload!.includes('claude-fable-5'));
  const result = entries.find((e) => e.type === 'call_result')!;
  assert.equal(result.call_id, req.call_id);
  assert.equal(result.payload, ANTHROPIC_BODY, 'exact response bytes recorded');
  assert.equal(result.tool?.name, 'payments_transfer', 'tool call indexed');

  const report = await verifyLedger(join(dir, 'ledger'));
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
});

test('record() links app-side execution via tool_use_id', async () => {
  const { attestor, ledgerPath } = newAttestor();
  const entry = attestor.record({
    tool_use_id: 'toolu_9xy',
    name: 'payments_transfer',
    input: { amount: '100.00' },
    output: { transfer_id: 'tx_1' },
  });
  await attestor.close();
  assert.ok(entry);
  assert.equal(entry.type, 'tool_execution');
  assert.equal(entry.call_id, 'toolu_9xy');
  const entries = readEntries(ledgerPath);
  assert.ok(entries.some((e) => e.type === 'tool_execution' && e.payload!.includes('tx_1')));
});

test('SSE tee: app stream unaffected, input_json_delta reconstructed', async () => {
  const { attestor, ledgerPath } = newAttestor();
  const events = [
    'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_s1","name":"payments_transfer"}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"amount\\":"}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\\"100.00\\"}"}}\n\n',
    'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
  ];
  const sseFetch = (async () => {
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        for (const ev of events) {
          controller.enqueue(new TextEncoder().encode(ev));
          await sleep(5);
        }
        controller.close();
      },
    });
    return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } });
  }) as typeof fetch;

  const wrapped = attestor.wrapFetch(sseFetch);
  const res = await wrapped('https://api.anthropic.com/v1/messages', { method: 'POST', body: '{}' });
  // app consumes the stream chunk by chunk, unaffected by the tee
  const appText = await res.text();
  assert.equal(appText, events.join(''));
  await sleep(100); // record side finishes at its own pace
  await attestor.close();

  const entries = readEntries(ledgerPath);
  const result = entries.find((e) => e.type === 'call_result')!;
  assert.equal(result.payload, events.join(''), 'raw SSE bytes recorded');
  assert.equal(result.tool?.name, 'payments_transfer', 'tool call reconstructed from deltas');
  const calls = extractToolCalls(result.payload!);
  assert.deepEqual(calls[0], { id: 'toolu_s1', name: 'payments_transfer', input: { amount: '100.00' } });
});

test('OpenAI streaming deltas also reconstruct', () => {
  const sse = [
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_z","function":{"name":"get_weather","arguments":""}}]}}]}',
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"city\\":"}}]}}]}',
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"Oslo\\"}"}}]}}]}',
    'data: [DONE]',
  ].join('\n');
  assert.deepEqual(extractToolCalls(sse), [{ id: 'call_z', name: 'get_weather', input: { city: 'Oslo' } }]);
});

test('block mode: failed ledger write rejects the call BEFORE dispatch', async () => {
  const { attestor } = newAttestor();
  const stub = stubFetch(ANTHROPIC_BODY);
  const wrapped = attestor.wrapFetch(stub.fetch);
  await attestor.close(); // ledger now closed → appends throw
  await assert.rejects(
    () => wrapped('https://api.anthropic.com/v1/messages', { method: 'POST', body: '{}' }),
    /closed/,
  );
  assert.equal(stub.calls.length, 0, 'request never dispatched without a record');
});

test('block mode: a failed streaming record leaves a gap marker, never silence', async () => {
  const { dir, attestor, ledgerPath } = newAttestor();
  const sse =
    'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x","name":"payments_transfer"}}\n\n' +
    'data: {"type":"content_block_stop","index":0}\n\n';
  const sseFetch = (async () =>
    new Response(sse, { status: 200, headers: { 'content-type': 'text/event-stream' } })) as typeof fetch;
  const wrapped = attestor.wrapFetch(sseFetch);

  // break the ledger only for the async response-record path
  const internal = (attestor as unknown as { ledger: { append: (...a: unknown[]) => unknown } }).ledger;
  const realAppend = internal.append.bind(internal);
  let broken = false;
  internal.append = (...args: unknown[]) => {
    if (broken) throw new Error('disk full (injected)');
    return realAppend(...args);
  };
  const res = await wrapped('https://api.anthropic.com/v1/messages', { method: 'POST', body: '{}' });
  broken = true;
  await res.text(); // app consumes the stream fine
  await sleep(120); // async record path fails here
  broken = false;
  await attestor.close();

  const entries = readEntries(ledgerPath);
  assert.ok(
    entries.some((e) => e.type === 'gap'),
    'block mode must not swallow the failure — a gap marker records the hole',
  );
  const report = await verifyLedger(join(dir, 'ledger'));
  assert.equal(report.exitCode, 0);
});

test('block mode refuses request bodies it cannot record byte-exactly', async () => {
  const { attestor } = newAttestor();
  const stub = stubFetch(OPENAI_CHAT_BODY);
  const wrapped = attestor.wrapFetch(stub.fetch);
  const form = new FormData();
  form.append('file', 'audio-bytes');
  await assert.rejects(
    () => wrapped('https://api.openai.com/v1/audio/transcriptions', { method: 'POST', body: form }),
    /cannot be recorded byte-exactly/,
  );
  assert.equal(stub.calls.length, 0, 'unrecordable call never dispatched in block mode');
  await attestor.close();
});

test('continue mode records an explicit note for unrecordable bodies', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const attestor = new Attestor({ ledger: join(dir, 'ledger'), keys, offline: true, failMode: 'continue' });
  const stub = stubFetch(OPENAI_CHAT_BODY);
  const wrapped = attestor.wrapFetch(stub.fetch);
  const form = new FormData();
  form.append('file', 'audio-bytes');
  const res = await wrapped('https://api.openai.com/v1/audio/transcriptions', { method: 'POST', body: form });
  assert.equal(res.status, 200);
  await attestor.close();
  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  const req = entries.find((e) => e.type === 'call_request')!;
  assert.ok(req.payload!.includes('not recordable byte-exactly'));
  assert.ok(req.payload!.includes('FormData'));
});

test('close() drains the anchor instead of racing a fixed sleep', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const attestor = new Attestor({ ledger: join(dir, 'ledger'), keys, offline: true });
  attestor.record({ name: 'x' });
  await attestor.close();
  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  const ckpt = entries.filter((e) => e.type === 'checkpoint');
  assert.ok(ckpt.length >= 1, 'final checkpoint written');
  // offline: the checkpoint must be queued for a later anchor, not forgotten
  const { readPending } = await import('../src/rekor.ts');
  assert.ok(readPending(join(dir, 'ledger')).length >= 1, 'unanchored checkpoint queued');
});

test('continue mode: call proceeds, gap marker on recovery', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const attestor = new Attestor({ ledger: join(dir, 'ledger'), keys, offline: true, failMode: 'continue' });
  const internal = (attestor as unknown as { ledger: { append: (...a: unknown[]) => unknown } }).ledger;
  const realAppend = internal.append.bind(internal);
  let broken = true;
  internal.append = (...args: unknown[]) => {
    if (broken) throw new Error('disk full (injected)');
    return realAppend(...args);
  };
  const stub = stubFetch(OPENAI_CHAT_BODY);
  const wrapped = attestor.wrapFetch(stub.fetch);
  const res = await wrapped('https://api.openai.com/v1/chat/completions', { method: 'POST', body: '{}' });
  assert.equal(res.status, 200, 'continue mode: app call unaffected');
  assert.equal(stub.calls.length, 1);
  broken = false;
  attestor.record({ name: 'noop' });
  await attestor.close();

  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  const gap = entries.find((e) => e.type === 'gap');
  assert.ok(gap, 'gap marker recorded after recovery');
});
