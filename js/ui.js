export const $ = (sel) => document.querySelector(sel);
export const $$ = (sel) => document.querySelectorAll(sel);

const NAMES = [
  'Onyx', 'Slate', 'Neon', 'Ember', 'Frost',
  'Volt', 'Dusk', 'Zinc', 'Rust', 'Jade',
  'Opal', 'Flint', 'Ash', 'Blaze', 'Coral',
  'Drift', 'Edge', 'Flux', 'Haze', 'Iron',
];

export function generateName() {
  return NAMES[Math.floor(Math.random() * NAMES.length)];
}

export function showView(id) {
  $$('.view').forEach(v => v.classList.remove('active'));
  $(`#${id}`).classList.add('active');
}

export function setStatus(text, className) {
  const el = $('#pairing-status');
  el.textContent = text;
  el.className = 'status ' + (className || '');
}

export function addMessage(text, source, time) {
  const log = $('#message-log');
  const card = document.createElement('div');
  card.className = `message-card ${source}`;

  const content = document.createElement('div');
  content.className = 'message-content';
  content.textContent = text;

  const meta = document.createElement('div');
  meta.className = 'message-meta';

  const ts = document.createElement('span');
  ts.textContent = formatTime(time);

  const copyBtn = document.createElement('button');
  copyBtn.textContent = 'copy';
  copyBtn.onclick = () => copyToClipboard(text);

  meta.appendChild(ts);
  meta.appendChild(copyBtn);
  card.appendChild(content);
  card.appendChild(meta);
  log.appendChild(card);
  log.scrollTop = log.scrollHeight;
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
}

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
