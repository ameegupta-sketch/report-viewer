'use strict';
const gate = document.getElementById('gate');
const frame = document.getElementById('report');
const bar = document.getElementById('controls');
const feedback = document.getElementById('feedback');
const form = document.getElementById('form');
const password = document.getElementById('password');
const submit = document.getElementById('unlock');
// Older bookmarks may still carry the original fragment. Everyone uses the same password form.
if (location.hash) history.replaceState(null, '', location.pathname + location.search);
try { sessionStorage.removeItem('private-report-key-v1'); } catch {}
const envelopeLabel = new TextEncoder().encode('Report password envelope v1');

async function getReportSecret(passphrase) {
  let envelope;
  try {
    const response = await fetch('./password-envelope.json', {credentials: 'omit'});
    if (!response.ok) throw new Error('load');
    envelope = await response.json();
  } catch {
    throw new Error('load');
  }
  const decode = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));
  if (envelope.version !== 1) throw new Error('format');
  const material = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const wrappingKey = await crypto.subtle.deriveKey(
    {name: 'PBKDF2', hash: 'SHA-256', salt: decode(envelope.salt), iterations: 1200000},
    material, {name: 'AES-GCM', length: 256}, false, ['decrypt']
  );
  const secret = await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv: decode(envelope.nonce), additionalData: envelopeLabel},
    wrappingKey, decode(envelope.ciphertext)
  );
  return new TextDecoder().decode(secret);
}

let pendingFile;
function getFile() {
  if (!pendingFile) pendingFile = fetch('./report.sealed', {credentials:'omit'}).then(response => {
    if (!response.ok) throw new Error('load');
    return response.arrayBuffer();
  }).catch(() => { pendingFile = null; throw new Error('load'); });
  return pendingFile;
}
async function decryptReport(buffer, accessKey, passphrase) {
  const bytes = new Uint8Array(buffer);
  const header = bytes.subarray(0, 40);
  if (bytes.length < 57 || new TextDecoder().decode(header.subarray(0, 8)) !== 'RPTLOCK1') throw new Error('format');
  const iterations = new DataView(buffer).getUint32(8, false);
  if (iterations !== 600000) throw new Error('format');
  const input = new TextEncoder().encode(accessKey + '\x00' + passphrase);
  const material = await crypto.subtle.importKey('raw',input,'PBKDF2',false,['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:header.subarray(12,28),iterations},
    material,{name:'AES-GCM',length:256},false,['decrypt']);
  const compressed = await crypto.subtle.decrypt({name:'AES-GCM',iv:header.subarray(28,40),additionalData:header,tagLength:128},
    key,bytes.subarray(40));
  const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Response(stream).text();
}
form.addEventListener('submit', async e => {
  e.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  const value = password.value;
  feedback.textContent = 'Opening your report…';
  try {
    const [payload, secret] = await Promise.all([getFile(), getReportSecret(value)]);
    const contents = await decryptReport(payload, secret, value);
    frame.srcdoc = contents;
    frame.hidden = false;
    bar.hidden = false;
    gate.hidden = true;
    password.value = '';
    feedback.textContent = '';
  } catch (error) {
    feedback.textContent = error.message === 'load' ? 'The report could not be loaded. Please try again.' :
      error.message === 'format' ? 'This report version could not be read. Reload the page and try again.' :
      'That password didn’t unlock the dashboard. Please try again.';
    password.select();
  } finally { submit.disabled = false; }
});
document.getElementById('lock').addEventListener('click',() => {
  frame.removeAttribute('srcdoc');
  frame.hidden = true;
  bar.hidden = true;
  gate.hidden = false;
  password.value = '';
  document.getElementById('copied').textContent = '';
  password.focus();
});
document.getElementById('copy').addEventListener('click',async () => {
  const link = new URL(location.pathname,location.origin);
  try { await navigator.clipboard.writeText(link.href); document.getElementById('copied').textContent='Dashboard link copied'; }
  catch { document.getElementById('copied').textContent='Copy the dashboard address from your browser.'; }
});
