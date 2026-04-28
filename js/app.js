import { RTCManager } from './rtc.js';
import { compress, decompress, generateNonce, UnknownVersionError } from './signaling.js';
import { computeSAS } from './sas.js';
import {
  MSG,
  encode,
  decode,
  SAS_CONFIRM_TYPE,
  SAS_CONFIRM_VERSION,
  encodeSasConfirm,
} from './protocol.js';
import { $, showView, setStatus, addMessage, generateName, copyToClipboard } from './ui.js';

let rtc = null;
let myName = '';
let peerName = '';
let aborted = false;
let busy = false;
let hasConnected = false;

// SAS handshake state. Reset on every fresh pairing attempt.
let sessionNonce = null;     // Uint8Array(2) — same on both peers, from the offer code
let localSAS = null;         // 7-char "XXX XXX" the local user is comparing
let userConfirmed = false;   // local user has tapped "they match"
let peerConfirmed = false;   // peer's sas-confirm message arrived AND its sas_value matched ours
let appUnlocked = false;     // app payload allowed in/out of the data channel

function init() {
  myName = generateName();
  $('#my-name').textContent = myName;

  // Pairing buttons
  $('#btn-create').addEventListener('click', startCreate);
  $('#btn-join').addEventListener('click', startJoin);

  // Initiator: submit answer code
  $('#btn-submit-answer').addEventListener('click', submitAnswer);
  $('#btn-copy-offer').addEventListener('click', () => {
    copyToClipboard($('#offer-code').value);
    $('#btn-copy-offer').textContent = 'Copied!';
    setTimeout(() => { $('#btn-copy-offer').textContent = 'Copy Code'; }, 1500);
  });

  // Joiner: submit offer code
  $('#btn-submit-offer').addEventListener('click', submitOffer);
  $('#btn-copy-answer').addEventListener('click', () => {
    copyToClipboard($('#answer-code').value);
    $('#btn-copy-answer').textContent = 'Copied!';
    setTimeout(() => { $('#btn-copy-answer').textContent = 'Copy Code'; }, 1500);
  });

  // SAS verify step
  $('#btn-sas-match').addEventListener('click', onUserConfirm);
  $('#btn-sas-mismatch').addEventListener('click', () => abortPairing(MISMATCH_COPY));

  // Connected view
  $('#btn-send').addEventListener('click', sendMessage);
  $('#message-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  // Home buttons (Start Over)
  document.querySelectorAll('[data-home]').forEach(btn => {
    btn.addEventListener('click', goHome);
  });

  // Disconnect / reconnect
  $('#btn-disconnect').addEventListener('click', doDisconnect);
  $('#btn-reconnect').addEventListener('click', goHome);
}

const MISMATCH_COPY = "Codes didn't match. Starting over is the right move — please try again.";
const VERSION_COPY  = 'This passcode was made by a different version of YEET. Both people need to be on the same version.';
const PROTOCOL_COPY = 'Connection aborted: unexpected message from peer.';

async function startCreate() {
  if (busy) return;
  busy = true;
  resetSasState();
  aborted = false;
  hasConnected = false;
  setStatus('generating offer...', 'connecting');
  hideAllSteps();

  rtc = new RTCManager();
  wireRTC();

  try {
    const sdp = await rtc.createOffer();
    if (aborted) return;
    sessionNonce = generateNonce();
    const code = await compress(sdp, sessionNonce);
    if (aborted) return;

    $('#offer-code').value = code;
    $('#pairing-offer').classList.remove('hidden');
    const wordCount = code.split(/\s+/).length;
    setStatus(`${wordCount} words — copy and share`, '');
  } catch (err) {
    if (!aborted) setStatus('error: ' + err.message, 'error');
  } finally {
    busy = false;
  }
}

function startJoin() {
  hideAllSteps();
  $('#pairing-join').classList.remove('hidden');
  setStatus('paste the room code and submit', '');
}

async function submitOffer() {
  const code = $('#offer-input').value.trim();
  if (!code || busy) return;

  busy = true;
  resetSasState();
  aborted = false;
  hasConnected = false;
  setStatus('processing offer...', 'connecting');

  rtc = new RTCManager();
  wireRTC();

  try {
    const { sdp: offerSDP, nonce } = await decompress(code);
    if (aborted) return;
    sessionNonce = nonce;
    // Answer code carries the same nonce (the joiner echoes it). The
    // initiator already has it — including it keeps the wire format symmetric
    // and lets the parser reject version skew on the answer leg too.
    const answerSDP = await rtc.acceptOffer(offerSDP);
    if (aborted) return;
    const answerCode = await compress(answerSDP, sessionNonce);
    if (aborted) return;

    $('#pairing-join').classList.add('hidden');
    $('#answer-code').value = answerCode;
    $('#pairing-answer').classList.remove('hidden');
    const wordCount = answerCode.split(/\s+/).length;
    setStatus(`${wordCount} words — copy and share back`, '');
  } catch (err) {
    if (aborted) return;
    if (err instanceof UnknownVersionError) {
      setStatus(VERSION_COPY, 'error');
    } else {
      setStatus('error: ' + err.message, 'error');
    }
  } finally {
    busy = false;
  }
}

async function submitAnswer() {
  const code = $('#answer-input').value.trim();
  if (!code || busy) return;

  busy = true;
  aborted = false;
  setStatus('connecting...', 'connecting');

  try {
    const { sdp: answerSDP, nonce } = await decompress(code);
    if (aborted) return;
    // Sanity check: the answer code's nonce must match the one we minted
    // on the offer. A mismatch means the joiner pasted the wrong code, the
    // user mixed up two sessions, or someone is replaying an old code.
    // Spec Decision #7 — distinct error path from SAS mismatch.
    if (!sessionNonce || nonce[0] !== sessionNonce[0] || nonce[1] !== sessionNonce[1]) {
      abortPairing('This passcode is for a different session. Ask the other person for a new one.');
      return;
    }
    await rtc.acceptAnswer(answerSDP);
  } catch (err) {
    if (aborted) return;
    if (err instanceof UnknownVersionError) {
      setStatus(VERSION_COPY, 'error');
      return;
    }
    setStatus('error: ' + err.message, 'error');
  } finally {
    busy = false;
  }
}

function wireRTC() {
  rtc.onMessage = (data) => {
    let parsed;
    try {
      parsed = decode(data);
    } catch {
      abortPairing(PROTOCOL_COPY);
      return;
    }

    // SAS confirm is the only message accepted before the app channel unlocks.
    if (parsed && parsed.type === SAS_CONFIRM_TYPE) {
      handlePeerConfirm(parsed);
      return;
    }

    if (!appUnlocked) {
      // Anything else arriving before unlock is a protocol violation.
      // Spec: receiver behavior step 1 — protocol error, abort.
      abortPairing(PROTOCOL_COPY);
      return;
    }

    if (parsed.t === MSG.HELLO) {
      peerName = parsed.name;
      $('#peer-name').textContent = peerName;
    } else if (parsed.t === MSG.CLIPBOARD) {
      addMessage(parsed.content, 'peer', parsed.ts);
    }
  };

  rtc.onStateChange = (state) => {
    if (aborted) return;
    if (state === 'connected') {
      hasConnected = true;
      enterSasStep();
    } else if (state === 'disconnected') {
      // Transient per WebRTC spec — ICE may recover on its own.
      return;
    } else if (state === 'failed' || state === 'closed') {
      if (hasConnected && appUnlocked) {
        showView('view-disconnected');
      } else if (hasConnected) {
        // DTLS came up but we never finished SAS confirm — treat as abort.
        abortPairing('Connection ended before verification finished.');
      } else {
        setStatus('connection failed — codes may have expired, start over', 'error');
      }
    }
  };
}

async function enterSasStep() {
  try {
    const fps = rtc.getFingerprints();
    if (!fps) throw new Error('fingerprints not available');
    if (!sessionNonce) throw new Error('session nonce missing');
    localSAS = await computeSAS(fps.local, fps.remote, sessionNonce);
  } catch (err) {
    abortPairing('Could not compute verification code: ' + err.message);
    return;
  }

  hideAllSteps();
  $('#sas-digits').textContent = localSAS;
  $('#pairing-sas').classList.remove('hidden');
  $('#btn-sas-match').disabled = false;
  $('#btn-sas-mismatch').disabled = false;
  setStatus('', '');
}

function onUserConfirm() {
  if (userConfirmed || !localSAS) return;
  userConfirmed = true;
  $('#btn-sas-match').disabled = true;
  // Send our local SAS to the peer; receiver checks it against theirs.
  rtc.send(encodeSasConfirm(localSAS));
  maybeUnlock();
  if (!appUnlocked) {
    setStatus('waiting for the other person to confirm...', 'connecting');
  }
}

function handlePeerConfirm(msg) {
  if (msg.version !== SAS_CONFIRM_VERSION) {
    abortPairing(VERSION_COPY);
    return;
  }
  if (typeof msg.sas_value !== 'string' || msg.sas_value !== localSAS) {
    // Spec Decision #9: receiver checks peer's sas_value matches local SAS;
    // mismatch is a hard abort. Catches byte-ordering / extraction bugs that
    // would otherwise silently produce divergent SAS values.
    console.warn('SAS mismatch in confirm message');
    abortPairing(MISMATCH_COPY);
    return;
  }
  if (peerConfirmed) return; // duplicate / replay — ignore
  peerConfirmed = true;
  maybeUnlock();
}

function maybeUnlock() {
  if (appUnlocked) return;
  if (!userConfirmed || !peerConfirmed) return;
  appUnlocked = true;
  rtc.send(encode(MSG.HELLO, { name: myName }));
  showView('view-connected');
}

function abortPairing(message) {
  if (aborted) return;
  aborted = true;
  busy = false;
  hasConnected = false;
  appUnlocked = false;
  if (rtc) {
    rtc.disconnect();
    rtc = null;
  }
  showView('view-pairing');
  resetPairing();
  setStatus(message, 'error');
}

function sendMessage() {
  if (!appUnlocked) return; // belt-and-braces; UI shouldn't be reachable
  const input = $('#message-input');
  const text = input.value.trim();
  if (!text) return;

  rtc.send(encode(MSG.CLIPBOARD, { content: text }));
  addMessage(text, 'self', Date.now());
  input.value = '';
  input.focus();
}

function goHome() {
  aborted = true;
  busy = false;
  hasConnected = false;
  resetSasState();
  if (rtc) {
    rtc.disconnect();
    rtc = null;
  }
  showView('view-pairing');
  resetPairing();
}

function doDisconnect() {
  hasConnected = false;
  appUnlocked = false;
  if (rtc) {
    rtc.disconnect();
    rtc = null;
  }
  showView('view-disconnected');
}

function resetSasState() {
  sessionNonce = null;
  localSAS = null;
  userConfirmed = false;
  peerConfirmed = false;
  appUnlocked = false;
}

function hideAllSteps() {
  $('#pairing-start').classList.add('hidden');
  $('#pairing-offer').classList.add('hidden');
  $('#pairing-join').classList.add('hidden');
  $('#pairing-answer').classList.add('hidden');
  $('#pairing-sas').classList.add('hidden');
}

function resetPairing() {
  hideAllSteps();
  $('#pairing-start').classList.remove('hidden');
  $('#offer-code').value = '';
  $('#answer-input').value = '';
  $('#offer-input').value = '';
  $('#answer-code').value = '';
  $('#sas-digits').textContent = '';
  $('#message-log').innerHTML = '';
}

init();
