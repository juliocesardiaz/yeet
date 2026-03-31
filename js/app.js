import { RTCManager } from './rtc.js';
import { compress, decompress } from './signaling.js';
import { MSG, encode, decode } from './protocol.js';
import { $, showView, setStatus, addMessage, generateName, copyToClipboard } from './ui.js';

let rtc = null;
let myName = '';
let peerName = '';

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

async function startCreate() {
  setStatus('generating offer...', 'connecting');
  hideAllSteps();

  rtc = new RTCManager();
  wireRTC();

  try {
    const sdp = await rtc.createOffer();
    const code = await compress(sdp);

    $('#offer-code').value = code;
    $('#pairing-offer').classList.remove('hidden');
    const wordCount = code.split(/\s+/).length;
    setStatus(`${wordCount} words — copy and share`, '');
  } catch (err) {
    setStatus('error: ' + err.message, 'error');
  }
}

function startJoin() {
  hideAllSteps();
  $('#pairing-join').classList.remove('hidden');
  setStatus('paste the room code and submit', '');
}

async function submitOffer() {
  const code = $('#offer-input').value.trim();
  if (!code) return;

  setStatus('processing offer...', 'connecting');

  rtc = new RTCManager();
  wireRTC();

  try {
    const offerSDP = await decompress(code);
    const answerSDP = await rtc.acceptOffer(offerSDP);
    const answerCode = await compress(answerSDP);

    $('#pairing-join').classList.add('hidden');
    $('#answer-code').value = answerCode;
    $('#pairing-answer').classList.remove('hidden');
    const wordCount = answerCode.split(/\s+/).length;
    setStatus(`${wordCount} words — copy and share back`, '');
  } catch (err) {
    setStatus('error: ' + err.message, 'error');
  }
}

async function submitAnswer() {
  const code = $('#answer-input').value.trim();
  if (!code) return;

  setStatus('connecting...', 'connecting');

  try {
    const answerSDP = await decompress(code);
    await rtc.acceptAnswer(answerSDP);
  } catch (err) {
    setStatus('error: ' + err.message, 'error');
  }
}

function wireRTC() {
  rtc.onMessage = (data) => {
    const msg = decode(data);
    if (msg.t === MSG.HELLO) {
      peerName = msg.name;
      $('#peer-name').textContent = peerName;
    } else if (msg.t === MSG.CLIPBOARD) {
      addMessage(msg.content, 'peer', msg.ts);
    } else if (msg.t === MSG.DISCONNECT) {
      doDisconnect();
    }
  };

  rtc.onStateChange = (state) => {
    if (state === 'connected') {
      rtc.send(encode(MSG.HELLO, { name: myName }));
      showView('view-connected');
    } else if (state === 'disconnected' || state === 'failed') {
      showView('view-disconnected');
    }
  };
}

function sendMessage() {
  const input = $('#message-input');
  const text = input.value.trim();
  if (!text) return;

  rtc.send(encode(MSG.CLIPBOARD, { content: text }));
  addMessage(text, 'self', Date.now());
  input.value = '';
  input.focus();
}

function goHome() {
  if (rtc) {
    rtc.disconnect();
    rtc = null;
  }
  showView('view-pairing');
  resetPairing();
}

function doDisconnect() {
  if (rtc) {
    rtc.send(encode(MSG.DISCONNECT));
    rtc.disconnect();
    rtc = null;
  }
  showView('view-disconnected');
}

function hideAllSteps() {
  $('#pairing-start').classList.add('hidden');
  $('#pairing-offer').classList.add('hidden');
  $('#pairing-join').classList.add('hidden');
  $('#pairing-answer').classList.add('hidden');
}

function resetPairing() {
  hideAllSteps();
  $('#pairing-start').classList.remove('hidden');
  $('#offer-code').value = '';
  $('#answer-input').value = '';
  $('#offer-input').value = '';
  $('#answer-code').value = '';
  $('#message-log').innerHTML = '';
  setStatus('', '');
}

init();
