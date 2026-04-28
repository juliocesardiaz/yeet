export const MSG = {
  HELLO: 'hello',
  CLIPBOARD: 'clipboard',
};

// SAS confirm rides on the same data channel but as a versioned envelope
// distinct from the application protocol — it has to be parseable before the
// app channel is unlocked. Format is fixed by spec Decision #9.
export const SAS_CONFIRM_TYPE = 'sas-confirm';
export const SAS_CONFIRM_VERSION = 1;

export function encodeSasConfirm(sasValue) {
  return JSON.stringify({
    type: SAS_CONFIRM_TYPE,
    version: SAS_CONFIRM_VERSION,
    sas_value: sasValue,
  });
}

export function encode(type, payload = {}) {
  return JSON.stringify({ t: type, ...payload, ts: Date.now() });
}

export function decode(data) {
  return JSON.parse(data);
}
