export const MSG = {
  HELLO: 'hello',
  CLIPBOARD: 'clipboard',
  PING: 'ping',
  PONG: 'pong',
  DISCONNECT: 'disconnect',
};

export function encode(type, payload = {}) {
  return JSON.stringify({ t: type, ...payload, ts: Date.now() });
}

export function decode(data) {
  return JSON.parse(data);
}
