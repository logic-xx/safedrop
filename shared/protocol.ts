export const HEADER = 24;
export const CHUNK = 256 * 1024;
export const MAX_META = 16 * 1024;
export const MAX_FRAME = HEADER + MAX_META + CHUNK;
export type Metadata = Record<string, unknown>;
export interface Frame { type: number; requestId: number; streamId: number; meta: Metadata; payload: Uint8Array }
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export function encode(type: number, requestId: number, meta: Metadata, payload: Uint8Array = new Uint8Array(0), streamId = 0): Uint8Array {
  const json = encoder.encode(JSON.stringify(meta));
  if (json.length > MAX_META || payload.length > CHUNK) throw new Error('FRAME_TOO_LARGE');
  const out = new Uint8Array(HEADER + json.length + payload.length);
  const h = new DataView(out.buffer);
  h.setUint32(0, 0x53465431); h.setUint8(4, 1); h.setUint8(5, type); h.setUint16(6, 0);
  h.setUint32(8, requestId); h.setUint32(12, streamId); h.setUint32(16, json.length); h.setUint32(20, payload.length);
  out.set(json, HEADER); out.set(payload, HEADER + json.length); return out;
}
export function decode(bytes: Uint8Array): Frame {
  if (bytes.length < HEADER || bytes.length > MAX_FRAME) throw new Error('INVALID_FRAME_LENGTH');
  const h = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (h.getUint32(0) !== 0x53465431 || h.getUint8(4) !== 1 || h.getUint16(6) !== 0 || ![1, 2].includes(h.getUint8(5))) throw new Error('INVALID_HEADER');
  const ml = h.getUint32(16), pl = h.getUint32(20);
  if (ml > MAX_META || pl > CHUNK || HEADER + ml + pl !== bytes.length) throw new Error('INVALID_FRAME_LENGTH');
  const meta: unknown = JSON.parse(decoder.decode(bytes.subarray(HEADER, HEADER + ml)));
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) throw new Error('INVALID_METADATA');
  return { type: h.getUint8(5), requestId: h.getUint32(8), streamId: h.getUint32(12), meta: meta as Metadata, payload: bytes.subarray(HEADER + ml) };
}
