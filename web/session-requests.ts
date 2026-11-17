import type { Frame, Metadata } from '../shared/protocol.ts';

interface RpcClient { rpc(op: string, meta?: Metadata, payload?: Uint8Array): Promise<Frame> }

// A delayed file read or response must never continue through a different login.
export function sessionRequests(client: RpcClient, expected: string, current: () => string) {
  const assertCurrent = () => {
    if (!expected || current() !== expected) throw new Error('TASK_SESSION_CHANGED');
  };
  return {
    assertCurrent,
    async rpc(op: string, meta?: Metadata, payload?: Uint8Array) {
      assertCurrent();
      const response = await client.rpc(op, meta, payload);
      assertCurrent();
      return response;
    },
  };
}
