#!/usr/bin/env node
// Minimal stdio MCP server with one echo tool. No dependencies.
// Used by attestor integration tests and the demo.
import { createInterface } from 'node:readline';

const TOOL = {
  name: 'echo',
  description: 'Echoes back the provided text.',
  inputSchema: {
    type: 'object',
    properties: { text: { type: 'string' } },
    required: ['text'],
  },
};

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

function replyError(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
}

const rl = createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return; // not JSON-RPC; ignore
  }
  if (msg.id === undefined) return; // notification — nothing to do
  switch (msg.method) {
    case 'initialize':
      reply(msg.id, {
        protocolVersion: msg.params?.protocolVersion ?? '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: { name: 'toy-mcp-server', version: '0.0.0' },
      });
      break;
    case 'tools/list':
      reply(msg.id, { tools: [TOOL] });
      break;
    case 'tools/call': {
      const { name, arguments: args } = msg.params ?? {};
      if (name !== 'echo') {
        replyError(msg.id, -32602, `unknown tool: ${name}`);
        break;
      }
      reply(msg.id, { content: [{ type: 'text', text: String(args?.text ?? '') }] });
      break;
    }
    case 'ping':
      reply(msg.id, {});
      break;
    default:
      replyError(msg.id, -32601, `method not found: ${msg.method}`);
  }
});
rl.on('close', () => process.exit(0));
