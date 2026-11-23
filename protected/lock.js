'use strict';
const gate = document.getElementById('gate');
const frame = document.getElementById('report');
const bar = document.getElementById('controls');
const feedback = document.getElementById('feedback');
const form = document.getElementById('form');
const password = document.getElementById('password');
const submit = document.getElementById('unlock');
const keyStore = 'private-report-key-v1';
const validKey = s => typeof s === 'string' && /^[A-Za-z0-9_-]{43}$/.test(s);
const incoming = new URLSearchParams(location.hash.slice(1)).get('access');
let access = validKey(incoming) ? incoming : '';
if (!access) { try { access = sessionStorage.getItem(keyStore) || ''; } catch {} }
if (validKey(incoming)) {
  try { sessionStorage.setItem(keyStore, incoming); } catch {}
  history.replaceState(null, '', location.pathname + location.search);
}
if (!validKey(access)) {
  form.hidden = true;
  feedback.textContent = 'Open the complete private link shared by the report owner to enter your password.';
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
  if (submit.disabled || !validKey(access)) return;
  submit.disabled = true;
  const value = password.value;
  feedback.textContent = 'Opening your report…';
  try {
    const contents = await decryptReport(await getFile(),access,value);
    frame.srcdoc = contents;
    frame.hidden = false;
    bar.hidden = false;
    gate.hidden = true;
    password.value = '';
    feedback.textContent = '';
  } catch (error) {
    feedback.textContent = error.message === 'load' ? 'The report could not be loaded. Please try again.' :
      error.message === 'format' ? 'This report version could not be read. Reload the page and try again.' :
      'The password or private link did not unlock this report.';
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
  link.hash = new URLSearchParams({access}).toString();
  try { await navigator.clipboard.writeText(link.href); document.getElementById('copied').textContent='Private link copied'; }
  catch { document.getElementById('copied').textContent='Copy the private link from the message that shared this report.'; }
});
