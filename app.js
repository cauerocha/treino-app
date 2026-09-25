/* ============================================================
   TREINO — app de treino local
   Núcleo: armazenamento, conta, modelo de dados, utilitários
   ============================================================ */

const APP_VERSION = '2.0.0';
const DB_KEY = 'treino.db.v2';

/* ---------- Armazenamento resiliente ---------- */
const Store = (() => {
  let memory = {};
  let ok = true;
  try {
    localStorage.setItem('__probe__', '1');
    localStorage.removeItem('__probe__');
  } catch (e) { ok = false; }
  return {
    persistent: ok,
    get(k) { if (!ok) return memory[k] || null; try { return localStorage.getItem(k); } catch (e) { return memory[k] || null; } },
    set(k, v) { if (!ok) { memory[k] = v; return; } try { localStorage.setItem(k, v); } catch (e) { ok = false; memory[k] = v; } },
    del(k) { if (!ok) { delete memory[k]; return; } try { localStorage.removeItem(k); } catch (e) {} }
  };
})();

/* ---------- SHA-256 em JS puro ----------
   Usado para guardar a senha com hash. Feito à mão porque
   crypto.subtle não existe quando o app roda de um arquivo
   local (file://) no Safari.                                  */
const sha256 = (() => {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

  const rr = (x, n) => (x >>> n) | (x << (32 - n));

  function bytes(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 63)); }
      else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
    }
    return out;
  }

  return function (msg) {
    const m = bytes(msg);
    const bitLen = m.length * 8;
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    for (let i = 7; i >= 0; i--) m.push((bitLen / Math.pow(2, i * 8)) & 0xff);

    let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const w = new Array(64);

    for (let i = 0; i < m.length; i += 64) {
      for (let t = 0; t < 16; t++)
        w[t] = (m[i+t*4] << 24) | (m[i+t*4+1] << 16) | (m[i+t*4+2] << 8) | m[i+t*4+3];
      for (let t = 16; t < 64; t++) {
        const s0 = rr(w[t-15],7) ^ rr(w[t-15],18) ^ (w[t-15] >>> 3);
        const s1 = rr(w[t-2],17) ^ rr(w[t-2],19) ^ (w[t-2] >>> 10);
        w[t] = (w[t-16] + s0 + w[t-7] + s1) | 0;
      }
      let [a,b,c,d,e,f,g,h] = H;
      for (let t = 0; t < 64; t++) {
        const S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[t] + w[t]) | 0;
        const S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22);
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) | 0;
        h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      H = H.map((v, i2) => (v + [a,b,c,d,e,f,g,h][i2]) | 0);
    }
    return H.map(v => ('00000000' + (v >>> 0).toString(16)).slice(-8)).join('');
  };
})();

/** Deriva o hash da senha com salt e várias voltas (dificulta força bruta) */
function hashSenha(senha, salt) {
  let h = salt + '|' + senha;
  for (let i = 0; i < 3000; i++) h = sha256(h + salt);
  return h;
}
function novoSalt() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36) + Math.random().toString(36).slice(2);
}

/* ---------- Modelo de dados ---------- */
const emptyDB = () => ({
  v: 2,
  account: null,          // { nome, email, salt, hash, criadoEm }
  profile: { photo: null, weight: null },
  routines: [],           // rotinas → treinos A/B/C
  sessions: [],
  active: null,
  settings: { restDefault: 60, sound: true, vibrate: true }
});

/* migração da versão 1 (fichas soltas) para a 2 (rotinas) */
function migrarV1() {
  try {
    const raw = Store.get('treino.db.v1');
    if (!raw) return null;
    const old = JSON.parse(raw);
    const db = emptyDB();
    db.sessions = old.sessions || [];
    db.settings = Object.assign(db.settings, old.settings || {});
    db.profile.weight = (old.profile || {}).weight || null;
    if ((old.workouts || []).length) {
      db.routines.push({
        id: uid(),
        name: 'Minha rotina',
        start: Date.now(),
        end: Date.now() + 1000 * 60 * 60 * 24 * 30,
        goal: 'Hipertrofia',
        level: 'Intermediário',
        archived: false,
        workouts: old.workouts
      });
    }
    if (old.profile && old.profile.name) {
      db.account = { nome: old.profile.name, email: '', salt: '', hash: '', criadoEm: Date.now(), semSenha: true };
    }
    return db;
  } catch (e) { return null; }
}

let DB = (() => {
  try {
    const raw = Store.get(DB_KEY);
    if (raw) {
      const p = JSON.parse(raw);
      return Object.assign(emptyDB(), p, {
        settings: Object.assign(emptyDB().settings, p.settings || {}),
        profile: Object.assign(emptyDB().profile, p.profile || {})
      });
    }
    const migrado = migrarV1();
    if (migrado) return migrado;
  } catch (e) {}
  return emptyDB();
})();

function save() {
  try { Store.set(DB_KEY, JSON.stringify(DB)); } catch (e) { console.warn(e); }
}

/* ---------- Sessão de login ---------- */
const AUTH_KEY = 'treino.auth.v2';
let logado = Store.get(AUTH_KEY) === '1';
function entrar() { logado = true; Store.set(AUTH_KEY, '1'); }
function sair() { logado = false; Store.del(AUTH_KEY); }

/* ---------- Utilitários ---------- */
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

const num = (v) => { const n = parseFloat(String(v == null ? '' : v).replace(',', '.')); return isNaN(n) ? 0 : n; };
const pad2 = (n) => String(n).padStart(2, '0');

function normalizaBusca(s) {
  return String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();
}

function youtubeId(url) {
  const m = String(url || '').match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|shorts\/))([\w-]{11})/);
  return m ? m[1] : null;
}
/* playsinline: no iPhone o vídeo toca dentro do modal, sem forçar tela cheia */
function youtubeEmbedUrl(url) {
  const id = youtubeId(url);
  return id ? `https://www.youtube.com/embed/${id}?playsinline=1&rel=0` : null;
}

function fmtClock(t) {
  const s = Math.max(0, Math.round(t));
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), x = s%60;
  return h ? `${h}:${pad2(m)}:${pad2(x)}` : `${m}:${pad2(x)}`;
}
function fmtDuration(ms) {
  const min = Math.round(ms/60000);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min/60), r = min%60;
  return r ? `${h}h ${r}min` : `${h}h`;
}
const MESES = ['jan','fev','mar','abr','mai','jun','jul','ago','set','out','nov','dez'];
const DIAS = ['dom','seg','ter','qua','qui','sex','sáb'];
const fmtDate = (ts) => { const d = new Date(ts); return `${DIAS[d.getDay()]}, ${d.getDate()} ${MESES[d.getMonth()]}`; };
const fmtBR = (ts) => { const d = new Date(ts); return `${pad2(d.getDate())}/${pad2(d.getMonth()+1)}/${d.getFullYear()}`; };
function fmtKg(v) {
  if (v == null || v === '' || isNaN(v)) return '—';
  const n = Number(v);
  return (Number.isInteger(n) ? n : n.toFixed(1).replace('.', ',')) + ' kg';
}
const startOfDay = (ts) => { const d = new Date(ts); d.setHours(0,0,0,0); return d.getTime(); };

/* ---------- Acesso ao modelo ---------- */
function rotinasAtivas() { return DB.routines.filter(r => !r.archived); }
function todasFichas() { return DB.routines.flatMap(r => (r.workouts || []).map(w => ({ rotina: r, ficha: w }))); }
function acharFicha(wid) {
  for (const r of DB.routines) {
    const w = (r.workouts || []).find(x => x.id === wid);
    if (w) return { rotina: r, ficha: w };
  }
  return null;
}
function sessoesDaFicha(wid) {
  return DB.sessions.filter(s => s.workoutId === wid && s.endedAt).sort((a,b) => b.endedAt - a.endedAt);
}

/* ---------- Cálculos ---------- */
function sessionVolume(s) {
  let t = 0;
  (s.items||[]).forEach(i => (i.sets||[]).forEach(x => { if (x.done) t += num(x.reps) * num(x.load); }));
  return t;
}
function sessionSetsDone(s) { let n=0; (s.items||[]).forEach(i => (i.sets||[]).forEach(x => { if (x.done) n++; })); return n; }
function sessionSetsTotal(s) { let n=0; (s.items||[]).forEach(i => n += (i.sets||[]).length); return n; }

function lastPerformance(nome, antesDe) {
  const alvo = String(nome||'').trim().toLowerCase();
  const past = DB.sessions.filter(s => s.endedAt && (!antesDe || s.endedAt < antesDe)).sort((a,b) => b.endedAt - a.endedAt);
  for (const s of past) {
    for (const it of (s.items||[])) {
      if (String(it.name||'').trim().toLowerCase() === alvo) {
        const feitas = (it.sets||[]).filter(x => x.done && num(x.load) > 0);
        if (feitas.length) {
          const best = feitas.reduce((a,b) => num(b.load) > num(a.load) ? b : a);
          return { load: num(best.load), reps: num(best.reps), when: s.endedAt };
        }
      }
    }
  }
  return null;
}

function lastSessionFull(nome, antesDe) {
  const alvo = String(nome||'').trim().toLowerCase();
  const past = DB.sessions.filter(s => s.endedAt && (!antesDe || s.endedAt < antesDe)).sort((a,b) => b.endedAt - a.endedAt);
  for (const s of past) {
    for (const it of (s.items||[])) {
      if (String(it.name||'').trim().toLowerCase() === alvo) {
        const feitas = (it.sets||[]).filter(x => x.done);
        if (feitas.length) return { when: s.endedAt, sets: feitas.map(x => ({ reps: x.reps, load: x.load })) };
      }
    }
  }
  return null;
}

function allExerciseNames() {
  const set = new Set();
  DB.routines.forEach(r => (r.workouts||[]).forEach(w => (w.items||[]).forEach(i => { if (i.name) set.add(i.name.trim()); })));
  DB.sessions.forEach(s => (s.items||[]).forEach(i => { if (i.name) set.add(i.name.trim()); }));
  return Array.from(set).sort((a,b) => a.localeCompare(b,'pt-BR'));
}

/* dias da semana atual (segunda a domingo) em que houve treino */
function frequenciaSemana() {
  const hoje = new Date(); hoje.setHours(0,0,0,0);
  const seg = new Date(hoje); seg.setDate(seg.getDate() - ((seg.getDay()+6)%7));
  const dias = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(seg); d.setDate(d.getDate()+i);
    const ini = d.getTime(), fim = ini + 86400000;
    dias.push({
      data: ini,
      letra: ['S','T','Q','Q','S','S','D'][i],
      treinou: DB.sessions.some(s => s.endedAt && s.endedAt >= ini && s.endedAt < fim),
      hoje: ini === hoje.getTime(),
      futuro: ini > hoje.getTime()
    });
  }
  return dias;
}

/* ---------- Feedback ---------- */
const Feedback = (() => {
  let ctx = null;
  function ensure() {
    if (!ctx) { const AC = window.AudioContext || window.webkitAudioContext; if (AC) ctx = new AC(); }
    if (ctx && ctx.state === 'suspended') ctx.resume();
    return ctx;
  }
  function tone(f, start, dur, g0) {
    const c = ensure(); if (!c) return;
    const o = c.createOscillator(), g = c.createGain();
    o.type = 'sine'; o.frequency.value = f;
    g.gain.setValueAtTime(0, c.currentTime+start);
    g.gain.linearRampToValueAtTime(g0, c.currentTime+start+0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, c.currentTime+start+dur);
    o.connect(g); g.connect(c.destination);
    o.start(c.currentTime+start); o.stop(c.currentTime+start+dur+0.05);
  }
  return {
    unlock: ensure,
    tick() { if (DB.settings.sound) tone(880,0,0.09,0.18); },
    finish() {
      if (DB.settings.sound) { tone(660,0,0.16,0.28); tone(880,0.18,0.16,0.28); tone(1180,0.36,0.32,0.3); }
      if (DB.settings.vibrate && navigator.vibrate) navigator.vibrate([120,70,120,70,240]);
    },
    tap() { if (DB.settings.vibrate && navigator.vibrate) navigator.vibrate(18); }
  };
})();

/* ---------- Toast e diálogo ---------- */
let toastTimer = null;
function toast(msg, kind) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast show' + (kind ? ' ' + kind : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 2600);
}

function confirmDialog(titulo, msg, label, perigo) {
  return new Promise(res => {
    const wrap = $('#modal');
    wrap.innerHTML = `<div class="modal-card">
      <h3>${esc(titulo)}</h3><p>${esc(msg)}</p>
      <div class="modal-actions">
        <button class="btn btn-ghost" data-mod="cancel">Cancelar</button>
        <button class="btn ${perigo === false ? 'btn-primary' : 'btn-danger'}" data-mod="ok">${esc(label||'Confirmar')}</button>
      </div></div>`;
    wrap.classList.add('show');
    wrap.onclick = ev => {
      const b = ev.target.closest('[data-mod]');
      if (!b && ev.target !== wrap) return;
      wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
      res(b ? b.dataset.mod === 'ok' : false);
    };
  });
}

/* ---------- Navegação ---------- */
const state = {
  tab: 'home',
  route: null,            // {name:'workout'|'editor'|'session'|'evolucao', ...}
  authMode: DB.account ? 'login' : 'signup',
  authErro: null,
  rotinaAberta: null,
  progressExercise: null,
  historyOpen: null,
  stack: []
};

function go(tab) { state.tab = tab; state.route = null; state.stack = []; window.scrollTo(0,0); render(); }
function openRoute(r) { if (state.route) state.stack.push(state.route); state.route = r; window.scrollTo(0,0); render(); }
function closeRoute() { state.route = state.stack.pop() || null; window.scrollTo(0,0); render(); }


/* ============================================================
   Tela de entrada: login e criar conta
   ============================================================ */

const LOGO_SVG = `<svg class="logo-mark" viewBox="0 0 24 24" aria-hidden="true">
  <path d="M6.5 6.5h2.2v11H6.5zM15.3 6.5h2.2v11h-2.2zM3 9.6h2.1v4.8H3zM18.9 9.6H21v4.8h-2.1zM8.7 11h6.6v2H8.7z"/>
</svg>`;

function viewAuth() {
  const criar = state.authMode === 'signup';
  const erro = state.authErro;

  return `
  <div class="auth">
    <div class="auth-brand">
      ${LOGO_SVG}
      <span class="logo-txt"><b>TREINO</b>PERSONAL</span>
    </div>

    <div class="auth-card">
      <div class="auth-tabs">
        <button type="button" class="auth-tab${!criar ? ' on' : ''}" data-act="auth-mode" data-v="login">Entrar</button>
        <button type="button" class="auth-tab${criar ? ' on' : ''}" data-act="auth-mode" data-v="signup">Criar conta</button>
      </div>

      <div id="auth-form">
        ${criar ? `
        <label class="field-label">Nome</label>
        <input class="input" type="text" id="au-nome" placeholder="Como quer ser chamado"
               autocomplete="off" value="${esc(state.authNome || '')}">` : ''}

        <label class="field-label">E-mail</label>
        <input class="input" type="text" id="au-email" placeholder="voce@email.com"
               inputmode="email" autocapitalize="none" autocorrect="off" autocomplete="off"
               value="${esc(state.authEmail || (!criar && DB.account ? DB.account.email : ''))}">

        <label class="field-label">Senha</label>
        <input class="input" type="password" id="au-senha" placeholder="${criar ? 'Mínimo 6 caracteres' : 'Sua senha'}" autocomplete="off">

        ${criar ? `
        <label class="field-label">Confirmar senha</label>
        <input class="input" type="password" id="au-senha2" placeholder="Repita a senha" autocomplete="off">` : ''}

        ${erro ? `<p class="auth-erro">${esc(erro)}</p>` : ''}

        <button type="button" class="btn btn-primary btn-block btn-lg" data-act="auth-go">
          ${criar ? 'Criar conta' : 'Entrar'}
        </button>
      </div>

      ${!criar && DB.account ? `<button type="button" class="link-btn" data-act="esqueci">Esqueci minha senha</button>` : ''}
      ${!criar && !DB.account ? `<p class="auth-hint">Você ainda não tem conta neste aparelho. Toque em <b>Criar conta</b>.</p>` : ''}
      ${criar && DB.account ? `<p class="auth-hint">Já existe uma conta neste aparelho (<b>${esc(DB.account.email || DB.account.nome)}</b>). Criar outra substitui a atual, mas mantém rotinas e histórico.</p>` : ''}
    </div>
  </div>`;
}

/** Mostra o erro SEM redesenhar a tela, para não apagar o que já foi digitado */
function erroAuth(msg) {
  state.authErro = msg;
  const form = document.getElementById('auth-form');
  if (!form) { render(); toast(msg, 'err'); return false; }

  let p = form.querySelector('.auth-erro');
  if (!p) {
    p = document.createElement('p');
    p.className = 'auth-erro';
    form.insertBefore(p, form.querySelector('[data-act="auth-go"]'));
  }
  p.textContent = msg;
  p.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  toast(msg, 'err');
  return false;
}

function emailValido(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(e || '').trim()); }

/** Lê um campo mesmo que o render tenha acontecido no meio do caminho */
function campo(id) { const el = document.getElementById(id); return el ? el.value : ''; }

function autenticar() {
  Feedback.unlock();
  if (state.authMode === 'signup') fazerCadastro(); else fazerLogin();
}

function fazerCadastro() {
  const nome = campo('au-nome').trim();
  const email = campo('au-email').trim().toLowerCase();
  const senha = campo('au-senha');
  const senha2 = campo('au-senha2');

  if (!nome) return erroAuth('Preencha seu nome.');
  if (!emailValido(email)) return erroAuth('E-mail inválido — precisa ter @ e um domínio, tipo voce@email.com.');
  if (senha.length < 6) return erroAuth('A senha precisa ter ao menos 6 caracteres.');
  if (senha !== senha2) return erroAuth('As duas senhas não são iguais.');

  const salt = novoSalt();
  DB.account = { nome, email, salt, hash: hashSenha(senha, salt), criadoEm: Date.now() };
  save();
  entrar();
  state.authErro = state.authNome = state.authEmail = null;
  toast(`Bem-vindo, ${nome.split(' ')[0]}!`);
  go('home');
}

function fazerLogin() {
  const email = campo('au-email').trim().toLowerCase();
  const senha = campo('au-senha');
  const c = DB.account;

  if (!c) return erroAuth('Nenhuma conta neste aparelho ainda — toque em Criar conta.');
  if (c.semSenha) { entrar(); state.authErro = null; go('home'); return; }
  if (!email) return erroAuth('Digite seu e-mail.');
  if (email !== c.email) return erroAuth('Esse e-mail não é o da conta deste aparelho.');
  if (!senha) return erroAuth('Digite sua senha.');
  if (hashSenha(senha, c.salt) !== c.hash) return erroAuth('Senha incorreta.');

  entrar();
  state.authErro = state.authNome = state.authEmail = null;
  go('home');
}

async function esqueciSenha() {
  const ok = await confirmDialog(
    'Redefinir senha',
    'Como tudo fica guardado só neste aparelho, não existe e-mail de recuperação. Posso definir uma senha nova agora — seus treinos e seu histórico continuam intactos.',
    'Definir nova senha', false);
  if (!ok) return;

  const wrap = $('#modal');
  wrap.innerHTML = `<div class="modal-card">
    <h3>Nova senha</h3>
    <input class="input" type="password" id="nova-senha" placeholder="Mínimo 6 caracteres" autocomplete="off">
    <input class="input" type="password" id="nova-senha2" placeholder="Repita a senha" autocomplete="off">
    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" data-mod="cancel">Cancelar</button>
      <button type="button" class="btn btn-primary" data-mod="ok">Salvar</button>
    </div></div>`;
  wrap.classList.add('show');
  wrap.onclick = ev => {
    const b = ev.target.closest('[data-mod]');
    if (!b) return;
    if (b.dataset.mod === 'ok') {
      const a = campo('nova-senha'), b2 = campo('nova-senha2');
      if (a.length < 6) return toast('Mínimo 6 caracteres', 'err');
      if (a !== b2) return toast('As senhas não são iguais', 'err');
      const salt = novoSalt();
      DB.account.salt = salt;
      DB.account.hash = hashSenha(a, salt);
      delete DB.account.semSenha;
      save();
      toast('Senha atualizada — agora é só entrar');
      state.authErro = null;
    }
    wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
    render();
  };
}


/* ============================================================
   Início
   ============================================================ */

function headerBrand(comVoltar, titulo) {
  return `
    <div class="brand-row">
      ${LOGO_SVG}
      <span class="logo-txt"><b>TREINO</b>PERSONAL</span>
    </div>
    ${comVoltar ? `<button class="back-link" data-act="close-route">
        <svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg> Voltar
      </button>` : ''}
    ${titulo ? `<h1 class="page-title">${esc(titulo)}</h1>` : ''}`;
}

function avatarHTML(tamanho) {
  const p = DB.profile.photo;
  const iniciais = (DB.account && DB.account.nome ? DB.account.nome : '?')
    .split(' ').filter(Boolean).slice(0, 2).map(x => x[0].toUpperCase()).join('');
  return `<div class="avatar ${tamanho || ''}" data-act="trocar-foto">
      ${p ? `<img src="${esc(p)}" alt="">` : `<span>${esc(iniciais)}</span>`}
      <div class="avatar-edit"><svg viewBox="0 0 24 24"><path d="M4 20h4l10.5-10.5a2.1 2.1 0 00-3-3L5 17v3z"/></svg></div>
    </div>`;
}

function saudacao() {
  const h = new Date().getHours();
  return h < 12 ? 'Bom dia' : h < 18 ? 'Boa tarde' : 'Boa noite';
}

function viewHome() {
  const nome = DB.account && DB.account.nome ? DB.account.nome.split(' ')[0] : '';
  const dias = frequenciaSemana();
  const total = DB.routines.reduce((a, r) => a + (r.workouts || []).length, 0);

  let html = `
  <div class="topwrap">
    ${headerBrand(false, null)}
    <div class="perfil-bloco">
      ${avatarHTML('grande')}
      <p class="perfil-nome">${esc(DB.account ? DB.account.nome : '')}</p>
    </div>
    <p class="saudacao">${saudacao()}, ${esc(nome)}!</p>

    <div class="card freq-card">
      <h3 class="card-title">Frequência de Treinos</h3>
      <div class="freq-dots">
        ${dias.map(d => `
          <div class="freq-dot${d.treinou ? ' feito' : ''}${d.hoje ? ' hoje' : ''}${d.futuro ? ' futuro' : ''}">
            <span class="dot">${d.treinou
              ? '<svg viewBox="0 0 24 24"><path d="M4 12.5l5 5L20 6.5"/></svg>'
              : (d.futuro ? '' : '<i></i>')}</span>
            <small>${d.letra}</small>
          </div>`).join('')}
      </div>
    </div>
  </div>

  <div class="body">`;

  /* treino em andamento */
  if (DB.active) {
    const feitas = sessionSetsDone(DB.active), tot = sessionSetsTotal(DB.active);
    const pct = tot ? Math.round(feitas / tot * 100) : 0;
    html += `
      <div class="card andamento" data-act="resume">
        <div class="andamento-top">
          <span class="tag tag-live">● Em andamento</span>
          <span class="andamento-clock">${fmtClock((Date.now() - DB.active.startedAt) / 1000)}</span>
        </div>
        <h4>${esc(DB.active.letter)} · ${esc(DB.active.workoutName)}</h4>
        <div class="bar"><i style="width:${pct}%"></i></div>
        <p class="andamento-meta">${feitas} de ${tot} séries — toque para continuar</p>
      </div>`;
  }

  /* bloco Treinos */
  html += `
    <button class="tile" data-act="tab" data-v="treinos">
      <span class="tile-icon">
        <svg viewBox="0 0 24 24"><path d="M6.5 7v10M17.5 7v10M3.5 9.5v5M20.5 9.5v5M6.5 12h11"/></svg>
      </span>
      <span class="tile-txt">
        <b>Treinos</b>
        <small>${total ? total + ' treino' + (total > 1 ? 's' : '') + ' na sua rotina' : 'nenhuma rotina ainda'}</small>
      </span>
      <svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg>
    </button>`;

  /* próximo treino sugerido */
  const prox = proximoTreino();
  if (prox && !DB.active) {
    const ult = sessoesDaFicha(prox.ficha.id)[0];
    html += `
      <h3 class="section-title">Próximo treino</h3>
      <div class="card treino-sugerido">
        <div class="tw-head">
          <div class="letra">${esc(prox.ficha.letter)}</div>
          <div class="tw-info">
            <h4>${esc(prox.ficha.name || 'Treino ' + prox.ficha.letter)}</h4>
            <p>${(prox.ficha.items || []).length} exercícios${ult ? ' · último em ' + fmtBR(ult.endedAt) : ' · nunca executado'}</p>
          </div>
        </div>
        <button class="btn btn-primary btn-block" data-act="start" data-w="${prox.ficha.id}">Iniciar treino</button>
      </div>`;
  }

  if (!total) {
    html += `
      <div class="empty">
        <div class="empty-icon">${LOGO_SVG}</div>
        <h3>Nenhuma rotina ainda</h3>
        <p>Importe a rotina que eu montar para você, ou crie a sua na aba Treinos.</p>
        <button class="btn btn-primary btn-block" data-act="tab" data-v="treinos">Ir para Treinos</button>
      </div>`;
  }

  html += `</div>`;
  return html;
}

/** Treino menos recentemente executado dentro das rotinas ativas */
function proximoTreino() {
  const cands = rotinasAtivas().flatMap(r => (r.workouts || []).map(w => ({ rotina: r, ficha: w })));
  if (!cands.length) return null;
  let melhor = null, melhorTs = Infinity;
  cands.forEach(c => {
    const u = sessoesDaFicha(c.ficha.id)[0];
    const ts = u ? u.endedAt : 0;
    if (ts < melhorTs) { melhorTs = ts; melhor = c; }
  });
  return melhor;
}

/* ---------- troca de foto de perfil ---------- */
function trocarFoto() {
  const inp = document.createElement('input');
  inp.type = 'file'; inp.accept = 'image/*';
  inp.onchange = () => {
    const f = inp.files && inp.files[0];
    if (!f) return;
    const fr = new FileReader();
    fr.onload = () => {
      const img = new Image();
      img.onload = () => {
        /* recorta quadrado e reduz para 240px, para não estourar o armazenamento */
        const S = 240;
        const cv = document.createElement('canvas');
        cv.width = S; cv.height = S;
        const ctx = cv.getContext('2d');
        const lado = Math.min(img.width, img.height);
        ctx.drawImage(img, (img.width - lado) / 2, (img.height - lado) / 2, lado, lado, 0, 0, S, S);
        DB.profile.photo = cv.toDataURL('image/jpeg', 0.82);
        save(); render();
        toast('Foto atualizada');
      };
      img.src = String(fr.result);
    };
    fr.readAsDataURL(f);
  };
  inp.click();
}


/* ============================================================
   Treinos: rotinas, fichas, detalhe, editor e evolução
   ============================================================ */

const LETRAS = ['A','B','C','D','E','F'];
const OBJETIVOS = ['Hipertrofia','Emagrecimento','Força','Resistência','Condicionamento'];
const NIVEIS = ['Iniciante','Intermediário','Avançado'];

const SUGESTOES = [
  'Supino reto com barra','Supino inclinado com halteres','Crucifixo na máquina','Crossover',
  'Flexão de braço','Desenvolvimento com halteres','Elevação lateral','Elevação frontal',
  'Remada curvada','Remada baixa','Puxada frontal','Barra fixa','Pulldown','Levantamento terra',
  'Agachamento livre','Leg press 45','Cadeira extensora','Mesa flexora','Cadeira flexora','Afundo',
  'Búlgaro','Stiff','Panturrilha em pé','Panturrilha sentado','Rosca direta','Rosca alternada',
  'Rosca martelo','Rosca scott','Tríceps testa','Tríceps corda','Tríceps francês','Mergulho no banco',
  'Abdominal supra','Abdominal infra','Prancha','Elevação de pernas','Encolhimento'
];

const VIDEOS_BANCO = [
  // { nome: 'Agachamento livre', url: 'https://www.youtube.com/watch?v=XXXXXXXXXXX' },
];

function datalistHTML() {
  const nomes = Array.from(new Set(allExerciseNames().concat(SUGESTOES)));
  return `<datalist id="dl-ex">${nomes.map(n => `<option value="${esc(n)}"></option>`).join('')}</datalist>`;
}

/* ------------------------------------------------------------
   LISTA DE ROTINAS
   ------------------------------------------------------------ */
function viewTreinos() {
  const arquivadas = DB.routines.filter(r => r.archived);
  const mostrando = state.verArquivadas ? arquivadas : rotinasAtivas();

  let html = `
  <div class="topwrap curto">
    ${headerBrand(false, 'Treinos')}
  </div>
  <div class="body">`;

  if (arquivadas.length) {
    html += `<div class="pills">
      <button class="pill-tab${!state.verArquivadas ? ' on' : ''}" data-act="ver-rotinas" data-v="0">Rotinas atuais</button>
      <button class="pill-tab${state.verArquivadas ? ' on' : ''}" data-act="ver-rotinas" data-v="1">Anteriores</button>
    </div>`;
  }

  if (!mostrando.length) {
    html += `<div class="empty">
      <div class="empty-icon">${LOGO_SVG}</div>
      <h3>${state.verArquivadas ? 'Nenhuma rotina anterior' : 'Nenhuma rotina ativa'}</h3>
      <p>Importe a rotina que eu montar para você, ou crie a sua do zero.</p>
    </div>`;
  }

  mostrando.forEach(r => {
    const aberta = state.rotinaAberta === r.id;
    html += `
      <div class="card rotina${aberta ? ' aberta' : ''}">
        <div class="rotina-head" data-act="abrir-rotina" data-r="${r.id}">
          <div class="rotina-icon">
            <svg viewBox="0 0 24 24"><path d="M6.5 7v10M17.5 7v10M3.5 9.5v5M20.5 9.5v5M6.5 12h11"/></svg>
          </div>
          <div class="rotina-info">
            <h4>${esc(r.name)}</h4>
            <p class="rotina-datas">
              <svg viewBox="0 0 24 24" class="ico-cal"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>
              ${r.start ? fmtBR(r.start) : '—'} – ${r.end ? fmtBR(r.end) : '—'}
            </p>
            <p class="rotina-tags">${esc(r.goal || '—')} | ${esc(r.level || '—')}</p>
          </div>
          <svg class="chev${aberta ? ' up' : ''}" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg>
        </div>
      </div>`;

    if (aberta) {
      (r.workouts || []).forEach((w, i) => {
        const feitos = sessoesDaFicha(w.id);
        html += `
          <div class="card treino-card">
            <h4 class="tc-titulo">Treino ${i + 1}</h4>
            <p class="tc-sub">TREINO ${esc(w.letter)}${w.name ? ' — ' + esc(w.name) : ''}</p>
            <p class="tc-exec">${feitos.length
              ? `Executado ${feitos.length} ${feitos.length > 1 ? 'vezes' : 'vez'}, última execução em ${fmtBR(feitos[0].endedAt)}`
              : 'Ainda não executado'}</p>
            <div class="tc-acoes">
              <button class="btn btn-outline btn-sm" data-act="evolucao" data-w="${w.id}">
                <svg viewBox="0 0 24 24" class="ico"><path d="M4 17l5-5 3 3 7-8"/></svg> Evolução
              </button>
              <button class="btn btn-outline btn-sm" data-act="editar-treino" data-w="${w.id}">
                <svg viewBox="0 0 24 24" class="ico"><path d="M4 20h4l10.5-10.5a2.1 2.1 0 00-3-3L5 17v3z"/></svg> Editar
              </button>
            </div>
            <button class="btn btn-primary btn-block" data-act="ver-treino" data-w="${w.id}">Ver treino</button>
          </div>`;
      });
      html += `
        <div class="rotina-tools">
          <button class="btn btn-ghost btn-sm" data-act="add-treino" data-r="${r.id}">+ Adicionar treino</button>
          <button class="btn btn-ghost btn-sm" data-act="editar-rotina" data-r="${r.id}">Editar rotina</button>
          <button class="btn btn-ghost btn-sm" data-act="${r.archived ? 'desarquivar' : 'arquivar'}" data-r="${r.id}">${r.archived ? 'Reativar' : 'Arquivar'}</button>
          <button class="btn btn-ghost btn-sm danger" data-act="del-rotina" data-r="${r.id}">Excluir</button>
        </div>`;
    }
  });

  html += `
    <button class="btn btn-primary btn-block" data-act="nova-rotina">+ Nova rotina</button>
    <button class="btn btn-outline btn-block" data-act="ir-importar">Importar rotina do personal</button>
  </div>`;
  return html;
}

/* ------------------------------------------------------------
   DETALHE DO TREINO
   ------------------------------------------------------------ */
function viewWorkout() {
  const achado = acharFicha(state.route.w);
  if (!achado) return '<p class="body">Treino não encontrado.</p>';
  const { rotina, ficha } = achado;
  const feitos = sessoesDaFicha(ficha.id);
  const series = (ficha.items || []).reduce((a, i) => a + (parseInt(i.sets) || 0), 0);

  let html = `
  <div class="topwrap curto">
    ${headerBrand(true, 'Treino ' + esc(ficha.letter))}
  </div>
  <div class="body">
    <div class="card resumo-treino">
      <div class="tw-head">
        <div class="letra">${esc(ficha.letter)}</div>
        <div class="tw-info">
          <h4>${esc(ficha.name || 'Treino ' + ficha.letter)}</h4>
          <p>${esc(rotina.name)}</p>
        </div>
      </div>
      <div class="mini-stats">
        <div><b>${(ficha.items || []).length}</b><small>exercícios</small></div>
        <div><b>${series}</b><small>séries</small></div>
        <div><b>${feitos.length}</b><small>execuções</small></div>
      </div>
      ${ficha.note ? `<div class="nota">${esc(ficha.note)}</div>` : ''}
      <button class="btn btn-primary btn-block btn-lg" data-act="start" data-w="${ficha.id}">Iniciar treino</button>
    </div>

    <h3 class="section-title">Exercícios</h3>`;

  if (!(ficha.items || []).length) {
    html += `<div class="card"><p class="vazio-txt">Nenhum exercício ainda. Toque em Editar para montar.</p></div>`;
  }

  (ficha.items || []).forEach((it, i) => {
    html += `
      <div class="card ex-item">
        <div class="ex-item-num">${i + 1}</div>
        <div class="ex-item-info">
          <h4>${esc(it.name || 'Exercício')}</h4>
          <p>${it.sets} × ${esc(it.reps || '—')}${it.load != null && it.load !== '' ? ' · ' + fmtKg(it.load) : ''} · ${it.rest}s de descanso</p>
        </div>
      </div>`;
  });

  html += `
    <button class="btn btn-outline btn-block" data-act="editar-treino" data-w="${ficha.id}">Editar treino</button>
    <button class="btn btn-ghost btn-block danger" data-act="del-treino" data-w="${ficha.id}">Excluir treino</button>
  </div>`;
  return html;
}

/* ------------------------------------------------------------
   EDITOR DE TREINO
   ------------------------------------------------------------ */
function viewEditor() {
  const achado = acharFicha(state.route.w);
  if (!achado) return '<p class="body">Treino não encontrado.</p>';
  const w = achado.ficha;

  let html = `
  <div class="topwrap curto">
    ${headerBrand(true, 'Editar treino')}
  </div>
  <div class="body">
    <div class="card">
      <label class="field-label">Letra</label>
      <div class="segmented">
        ${LETRAS.map(l => `<button class="seg${w.letter === l ? ' on' : ''}" data-act="set-letter" data-w="${w.id}" data-v="${l}">${l}</button>`).join('')}
      </div>
      <label class="field-label">Nome do treino</label>
      <input class="input" type="text" placeholder="Ex.: Peito, ombro e tríceps" value="${esc(w.name)}" data-w="${w.id}" data-f="name">
      <label class="field-label">Observações</label>
      <textarea class="input" rows="2" placeholder="Aquecimento, cadência, avisos..." data-w="${w.id}" data-f="note">${esc(w.note || '')}</textarea>
    </div>

    <h3 class="section-title">Exercícios</h3>`;

  (w.items || []).forEach((it, idx) => html += exEditorCard(w, it, idx));

  html += `
    <button class="btn btn-primary btn-block" data-act="add-ex" data-w="${w.id}">+ Adicionar exercício</button>
  </div>
  ${datalistHTML()}`;
  return html;
}

function exEditorCard(w, it, idx) {
  const total = (w.items || []).length;
  return `
    <div class="card ex-edit">
      <div class="ex-edit-head">
        <span class="ex-num">${idx + 1}</span>
        <input class="input input-flush" type="text" list="dl-ex" placeholder="Nome do exercício"
               value="${esc(it.name)}" data-w="${w.id}" data-i="${it.id}" data-f="name">
        <div class="ex-order">
          <button class="icon-btn sm" data-act="move-up" data-w="${w.id}" data-i="${it.id}" ${idx === 0 ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24"><path d="M6 15l6-6 6 6"/></svg></button>
          <button class="icon-btn sm" data-act="move-down" data-w="${w.id}" data-i="${it.id}" ${idx === total - 1 ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg></button>
          <button class="icon-btn sm danger" data-act="del-ex" data-w="${w.id}" data-i="${it.id}">
            <svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg></button>
        </div>
      </div>
      <div class="grid-4">
        <div><label>Séries</label><input class="input" type="number" inputmode="numeric" min="1" max="20" value="${esc(it.sets)}" data-w="${w.id}" data-i="${it.id}" data-f="sets"></div>
        <div><label>Reps</label><input class="input" type="text" placeholder="8-12" value="${esc(it.reps)}" data-w="${w.id}" data-i="${it.id}" data-f="reps"></div>
        <div><label>Carga</label><input class="input" type="number" inputmode="decimal" step="0.5" placeholder="kg" value="${it.load == null ? '' : esc(it.load)}" data-w="${w.id}" data-i="${it.id}" data-f="load"></div>
        <div><label>Desc. (s)</label><input class="input" type="number" inputmode="numeric" step="5" placeholder="60" value="${esc(it.rest)}" data-w="${w.id}" data-i="${it.id}" data-f="rest"></div>
      </div>
      <input class="input input-note" type="text" placeholder="Técnica / observação (opcional)" value="${esc(it.note || '')}" data-w="${w.id}" data-i="${it.id}" data-f="note">
      <button class="btn btn-ghost btn-xs" data-act="video-picker" data-w="${w.id}" data-i="${it.id}">${it.video ? 'Vídeo adicionado ✓' : 'Vídeo'}</button>
    </div>`;
}

/* ------------------------------------------------------------
   EVOLUÇÃO DE UM TREINO
   ------------------------------------------------------------ */
function viewEvolucao() {
  const achado = acharFicha(state.route.w);
  if (!achado) return '<p class="body">Treino não encontrado.</p>';
  const ficha = achado.ficha;
  const nomes = (ficha.items || []).map(i => (i.name || '').trim()).filter(Boolean);
  const sel = state.progressExercise && nomes.includes(state.progressExercise) ? state.progressExercise : nomes[0];
  const feitos = sessoesDaFicha(ficha.id);

  let html = `
  <div class="topwrap curto">
    ${headerBrand(true, 'Evolução')}
  </div>
  <div class="body">
    <div class="card">
      <h4 class="card-title">Treino ${esc(ficha.letter)}${ficha.name ? ' — ' + esc(ficha.name) : ''}</h4>
      <div class="mini-stats">
        <div><b>${feitos.length}</b><small>execuções</small></div>
        <div><b>${feitos.length ? Math.round(feitos.reduce((a,s) => a + sessionVolume(s), 0) / feitos.length).toLocaleString('pt-BR') : 0}</b><small>kg médios</small></div>
        <div><b>${feitos.length ? fmtDuration(feitos.reduce((a,s) => a + (s.endedAt - s.startedAt), 0) / feitos.length) : '—'}</b><small>duração média</small></div>
      </div>
    </div>`;

  if (!nomes.length) {
    html += `<div class="card"><p class="vazio-txt">Este treino ainda não tem exercícios.</p></div></div>`;
    return html;
  }

  html += `
    <h3 class="section-title">Carga por exercício</h3>
    <div class="card chart-card">
      <select class="input select" data-act="pick-progress">
        ${nomes.map(n => `<option value="${esc(n)}"${n === sel ? ' selected' : ''}>${esc(n)}</option>`).join('')}
      </select>
      <canvas id="chart" height="180"></canvas>
      <div class="chart-legend" id="chart-legend"></div>
    </div>
  </div>`;
  return html;
}

/* ------------------------------------------------------------
   Ações
   ------------------------------------------------------------ */
function novaRotina() {
  const hoje = new Date(); hoje.setHours(0,0,0,0);
  const fim = new Date(hoje); fim.setMonth(fim.getMonth() + 1);
  const r = {
    id: uid(), name: 'Nova rotina', start: hoje.getTime(), end: fim.getTime(),
    goal: 'Hipertrofia', level: 'Iniciante', archived: false, workouts: []
  };
  DB.routines.unshift(r);
  addTreino(r.id, true);
  save();
  state.rotinaAberta = r.id;
  state.verArquivadas = false;
  render();
  editarRotina(r.id);
}

function addTreino(rid, silencioso) {
  const r = DB.routines.find(x => x.id === rid);
  if (!r) return;
  r.workouts = r.workouts || [];
  const usadas = r.workouts.map(w => w.letter);
  const letra = LETRAS.find(l => !usadas.includes(l)) || 'A';
  const w = { id: uid(), letter: letra, name: '', note: '', items: [] };
  addExercicio(w);
  r.workouts.push(w);
  save();
  if (!silencioso) render();
  return w;
}

function addExercicio(w) {
  w.items = w.items || [];
  w.items.push({ id: uid(), name: '', sets: 3, reps: '10', load: null, rest: DB.settings.restDefault, note: '', video: '' });
}

function abrirPickerVideo(wid, iid) {
  const achado = acharFicha(wid);
  if (!achado) return;
  const it = (achado.ficha.items || []).find(x => x.id === iid);
  if (!it) return;

  let draft = it.video || '';

  const draw = (q) => {
    const alvo = normalizaBusca(q || '');
    const lista = VIDEOS_BANCO.filter(v => normalizaBusca(v.nome).includes(alvo));
    const wrap = $('#modal');
    wrap.innerHTML = `<div class="modal-card grande">
      <h3>Vídeo — ${esc(it.name || 'Exercício')}</h3>
      <div class="video-search">
        <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input class="input" id="vid-busca" type="text" placeholder="Buscar no banco de vídeos" value="${esc(q || '')}">
      </div>
      <div id="vid-lista" class="video-lista">
        ${lista.length ? lista.map(v => `<button class="video-item" data-mod="pick" data-url="${esc(v.url)}">${esc(v.nome)}</button>`).join('')
          : `<p class="vazio-txt">${VIDEOS_BANCO.length ? 'Nenhum vídeo encontrado.' : 'Banco de vídeos ainda vazio.'}</p>`}
      </div>
      <label class="field-label">Ou cole o link do seu vídeo</label>
      <input class="input" id="vid-link" type="text" placeholder="https://..." value="${draft && !VIDEOS_BANCO.some(v => v.url === draft) ? esc(draft) : ''}">
      <div class="modal-actions">
        <button class="btn btn-ghost" data-mod="cancel">Cancelar</button>
        <button class="btn btn-primary" data-mod="ok">Salvar</button>
      </div></div>`;
    wrap.classList.add('show');

    $('#vid-busca').oninput = (ev) => draw(ev.target.value);
    $('#vid-link').oninput = (ev) => { draft = ev.target.value; };
    setTimeout(() => { const b = $('#vid-busca'); if (b) { b.focus(); b.selectionStart = b.selectionEnd = b.value.length; } }, 0);

    wrap.onclick = ev => {
      const b = ev.target.closest('[data-mod]');
      if (!b && ev.target !== wrap) return;
      if (b && b.dataset.mod === 'pick') { draft = b.dataset.url; draw(''); return; }
      let salvar = false;
      if (b && b.dataset.mod === 'ok') { it.video = draft.trim(); save(); salvar = true; }
      wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
      if (salvar) render();
    };
  };
  draw('');
}

function abrirUltimoRegistro(nome, nota) {
  const hist = lastSessionFull(nome);
  const wrap = $('#modal');
  wrap.innerHTML = `<div class="modal-card grande">
    <h3>${esc(nome || 'Exercício')}</h3>
    ${nota ? `<p class="ex-item-obs">${esc(nota)}</p>` : ''}
    ${hist ? `
      <p class="ur-data">Última vez em ${fmtBR(hist.when)}</p>
      <div class="hist-head"><span>Série</span><span>Reps</span><span>Carga</span></div>
      ${hist.sets.map((s, i2) => `
        <div class="hist-row">
          <span class="set-n">${i2 + 1}</span>
          <span>${esc(s.reps)}</span>
          <span>${fmtKg(s.load)}</span>
        </div>`).join('')}
    ` : `<p class="vazio-txt">Sem histórico ainda.</p>`}
    <div class="modal-actions">
      <button class="btn btn-primary" data-mod="ok">Fechar</button>
    </div></div>`;
  wrap.classList.add('show');
  wrap.onclick = ev => {
    const b = ev.target.closest('[data-mod]');
    if (!b && ev.target !== wrap) return;
    wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
  };
}

function abrirVideoExercicio(nome, url) {
  const embed = youtubeEmbedUrl(url);
  if (!embed) return;
  const wrap = $('#modal');
  wrap.innerHTML = `<div class="modal-card">
    <h3>${esc(nome || 'Exercício')}</h3>
    <div class="video-frame"><iframe src="${esc(embed)}" allow="autoplay; encrypted-media; picture-in-picture" allowfullscreen></iframe></div>
    <div class="modal-actions">
      <button class="btn btn-primary" data-mod="ok">Fechar</button>
    </div></div>`;
  wrap.classList.add('show');
  wrap.onclick = ev => {
    const b = ev.target.closest('[data-mod]');
    if (!b && ev.target !== wrap) return;
    wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
  };
}

function editarRotina(rid) {
  const r = DB.routines.find(x => x.id === rid);
  if (!r) return;
  const iso = ts => { const d = new Date(ts || Date.now()); return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}`; };
  const wrap = $('#modal');
  wrap.innerHTML = `<div class="modal-card">
    <h3>Rotina</h3>
    <label class="field-label">Nome</label>
    <input class="input" id="r-nome" value="${esc(r.name)}" placeholder="Ex.: Treino 1 – Adaptação e progressão">
    <div class="grid-2">
      <div><label class="field-label">Início</label><input class="input" type="date" id="r-ini" value="${iso(r.start)}"></div>
      <div><label class="field-label">Fim</label><input class="input" type="date" id="r-fim" value="${iso(r.end)}"></div>
    </div>
    <label class="field-label">Objetivo</label>
    <select class="input select" id="r-obj">${OBJETIVOS.map(o => `<option${o === r.goal ? ' selected' : ''}>${o}</option>`).join('')}</select>
    <label class="field-label">Nível</label>
    <select class="input select" id="r-niv">${NIVEIS.map(o => `<option${o === r.level ? ' selected' : ''}>${o}</option>`).join('')}</select>
    <div class="modal-actions">
      <button class="btn btn-ghost" data-mod="cancel">Cancelar</button>
      <button class="btn btn-primary" data-mod="ok">Salvar</button>
    </div></div>`;
  wrap.classList.add('show');
  wrap.onclick = ev => {
    const b = ev.target.closest('[data-mod]');
    if (!b) return;
    if (b.dataset.mod === 'ok') {
      r.name = $('#r-nome').value.trim() || 'Rotina';
      r.start = new Date($('#r-ini').value + 'T00:00:00').getTime() || r.start;
      r.end = new Date($('#r-fim').value + 'T00:00:00').getTime() || r.end;
      r.goal = $('#r-obj').value;
      r.level = $('#r-niv').value;
      save();
    }
    wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
    render();
  };
}


/* ============================================================
   Modo execução: treino ativo, séries e cronômetro de descanso
   ============================================================ */

function iniciarTreino(wid) {
  const achado = acharFicha(wid);
  if (!achado) return;
  const w = achado.ficha;
  const itens = (w.items || []).filter(i => (i.name || '').trim());
  if (!itens.length) { toast('Este treino ainda não tem exercícios', 'err'); return; }

  const começar = () => {
    Feedback.unlock();
    DB.active = {
      id: uid(),
      workoutId: w.id,
      workoutName: w.name || 'Treino ' + w.letter,
      letter: w.letter || '',
      routineName: achado.rotina.name,
      note: w.note || '',
      startedAt: Date.now(),
      endedAt: null,
      rest: null,
      open: null,
      items: itens.map(it => ({
        id: uid(),
        name: it.name,
        targetReps: it.reps || '',
        targetLoad: it.load,
        rest: parseInt(it.rest) || DB.settings.restDefault,
        note: it.note || '',
        video: it.video || '',
        prev: lastPerformance(it.name),
        sets: Array.from({ length: Math.max(1, parseInt(it.sets) || 1) },
          () => ({ reps: '', load: '', done: false, at: null }))
      }))
    };
    DB.active.open = (DB.active.items[0] || {}).id || null;
    save();
    openRoute({ name: 'session' });
  };

  if (DB.active) {
    confirmDialog('Treino em andamento',
      'Você já tem um treino aberto. Iniciar outro vai descartar o atual.', 'Descartar e iniciar')
      .then(ok => { if (ok) começar(); });
  } else começar();
}

function viewSession() {
  const s = DB.active;
  if (!s) return '<p class="body">Nenhum treino em andamento.</p>';
  const feitas = sessionSetsDone(s), total = sessionSetsTotal(s);
  const pct = total ? (feitas / total * 100) : 0;

  let html = `
  <div class="sess-top">
    <button class="icon-btn lg" data-act="close-route" aria-label="Voltar">
      <svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
    </button>
    <div class="sess-top-mid">
      <span class="sess-top-title">Treino ${esc(s.letter)}${s.workoutName ? ' · ' + esc(s.workoutName) : ''}</span>
      <span class="sess-top-clock" id="sess-clock">${fmtClock((Date.now() - s.startedAt) / 1000)}</span>
    </div>
    <button class="btn btn-primary btn-xs" data-act="finish">Finalizar</button>
  </div>

  <div class="sess-progress">
    <div class="bar"><i id="sess-bar" style="width:${pct}%"></i></div>
    <span id="sess-count">${feitas}/${total} séries</span>
  </div>

  <div class="body sess-body">`;

  if (s.note) html += `<div class="nota">${esc(s.note)}</div>`;

  s.items.forEach((it, idx) => {
    const done = it.sets.filter(x => x.done).length;
    const completo = done === it.sets.length;
    const aberto = s.open === it.id;
    const yt = youtubeId(it.video);
    html += `
      <div class="card ex-run${completo ? ' completo' : ''}${aberto ? ' aberto' : ''}">
        <div class="ex-run-head" data-act="toggle-ex" data-i="${it.id}">
          <div class="ex-run-check">${completo
            ? '<svg viewBox="0 0 24 24" class="tick"><path d="M4 12.5l5 5L20 6.5"/></svg>'
            : `<span>${idx + 1}</span>`}</div>
          <div class="ex-run-info">
            <h4>${esc(it.name)}</h4>
            <p>${it.sets.length} × ${esc(it.targetReps || '—')}${it.targetLoad != null && it.targetLoad !== '' ? ' · ' + fmtKg(it.targetLoad) : ''} · ${it.rest}s</p>
          </div>
          <span class="ex-run-badge">${done}/${it.sets.length}</span>
          ${yt ? `<button class="ex-run-thumb" data-act="ver-video" data-s="${it.id}" aria-label="Ver vídeo">
            <img src="https://i.ytimg.com/vi/${yt}/mqdefault.jpg" loading="lazy" alt="">
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="12"/><path d="M10 7.5l6 4.5-6 4.5z"/></svg>
          </button>` : ''}
        </div>`;

    if (aberto) {
      html += `<div class="sets">
        <button class="btn btn-ghost btn-xs ur-btn" data-act="ultimo-registro" data-s="${it.id}">Último registro</button>
        <div class="sets-head"><span>Série</span><span>Reps</span><span>Carga</span><span></span></div>`;
      it.sets.forEach((st, si) => {
        const phL = it.targetLoad != null && it.targetLoad !== '' ? it.targetLoad : (it.prev ? it.prev.load : '');
        html += `
          <div class="set-row${st.done ? ' feita' : ''}">
            <span class="set-n">${si + 1}</span>
            <input class="input set-in" type="number" inputmode="numeric" placeholder="${esc(it.targetReps || '')}"
                   value="${esc(st.reps)}" data-s="${it.id}" data-si="${si}" data-f="reps">
            <input class="input set-in" type="number" inputmode="decimal" step="0.5" placeholder="${esc(phL)}"
                   value="${esc(st.load)}" data-s="${it.id}" data-si="${si}" data-f="load">
            <button class="check${st.done ? ' on' : ''}" data-act="toggle-set" data-s="${it.id}" data-si="${si}">
              <svg viewBox="0 0 24 24"><path d="M4 12.5l5 5L20 6.5"/></svg>
            </button>
          </div>`;
      });
      html += `<div class="set-tools">
          <button class="btn btn-ghost btn-xs" data-act="add-set" data-s="${it.id}">+ série</button>
          ${it.sets.length > 1 ? `<button class="btn btn-ghost btn-xs" data-act="rm-set" data-s="${it.id}">− série</button>` : ''}
          <button class="btn btn-ghost btn-xs" data-act="rest-now" data-s="${it.id}">descanso ${it.rest}s</button>
        </div></div>`;
    }
    html += `</div>`;
  });

  html += `<button class="btn btn-ghost btn-block danger" data-act="discard">Descartar treino</button></div>

  <div class="rest-bar${s.rest ? ' show' : ''}" id="rest-bar">
    <div class="rest-progress"><i id="rest-progress" style="width:0%"></i></div>
    <button class="rest-adj" data-act="rest-add" data-v="-15">−15s</button>
    <div class="rest-mid">
      <span class="rest-count" id="rest-count">${s.rest ? fmtClock((s.rest.endsAt - Date.now()) / 1000) : '0:00'}</span>
      <span class="rest-lbl">descanso</span>
    </div>
    <button class="rest-adj" data-act="rest-add" data-v="15">+15s</button>
    <button class="rest-skip" data-act="rest-skip">Pular</button>
  </div>`;
  return html;
}

const itemAtivo = (iid) => DB.active ? DB.active.items.find(x => x.id === iid) : null;

function toggleSet(iid, si) {
  const it = itemAtivo(iid); if (!it) return;
  const st = it.sets[si]; if (!st) return;
  st.done = !st.done;
  if (st.done) {
    if (st.reps === '' || st.reps == null) {
      const alvo = String(it.targetReps || '').match(/\d+/);
      st.reps = alvo ? alvo[0] : '';
    }
    if (st.load === '' || st.load == null)
      st.load = (it.targetLoad != null && it.targetLoad !== '') ? it.targetLoad : (it.prev ? it.prev.load : '');
    st.at = Date.now();
    Feedback.tap();
    iniciarDescanso(it.rest);
    if (it.sets.every(x => x.done)) {
      const idx = DB.active.items.findIndex(x => x.id === iid);
      const prox = DB.active.items.slice(idx + 1).find(x => !x.sets.every(y => y.done));
      if (prox) DB.active.open = prox.id;
    }
  } else st.at = null;
  save(); render();
}

function addSet(iid) {
  const it = itemAtivo(iid); if (!it) return;
  const u = it.sets[it.sets.length - 1];
  it.sets.push({ reps: '', load: u ? u.load : '', done: false, at: null });
  save(); render();
}
function rmSet(iid) {
  const it = itemAtivo(iid); if (!it || it.sets.length <= 1) return;
  it.sets.pop(); save(); render();
}

function iniciarDescanso(seg) {
  const s = Math.max(0, parseInt(seg) || 0);
  if (!s || !DB.active) return;
  DB.active.rest = { endsAt: Date.now() + s * 1000, total: s, alerted: false };
  save();
}
function ajustarDescanso(d) {
  if (!DB.active || !DB.active.rest) return;
  const r = DB.active.rest;
  r.endsAt += d * 1000;
  r.total = Math.max(5, r.total + d);
  if (r.endsAt <= Date.now()) DB.active.rest = null;
  save(); render();
}
function pularDescanso() { if (DB.active) { DB.active.rest = null; save(); render(); } }

function tickTimers() {
  if (!DB.active || !state.route || state.route.name !== 'session') return;
  const c = document.getElementById('sess-clock');
  if (c) c.textContent = fmtClock((Date.now() - DB.active.startedAt) / 1000);

  const bar = document.getElementById('rest-bar');
  const r = DB.active.rest;
  if (!bar) return;
  if (!r) { bar.classList.remove('show'); return; }

  const restante = (r.endsAt - Date.now()) / 1000;
  bar.classList.add('show');
  const cnt = document.getElementById('rest-count');
  const prog = document.getElementById('rest-progress');
  if (cnt) cnt.textContent = fmtClock(Math.max(0, restante));
  if (prog) prog.style.width = Math.max(0, Math.min(100, (1 - restante / r.total) * 100)) + '%';

  if (restante <= 3.2 && restante > 0 && !r.b3) { r.b3 = true; Feedback.tick(); }
  if (restante <= 2.2 && restante > 0 && !r.b2) { r.b2 = true; Feedback.tick(); }
  if (restante <= 1.2 && restante > 0 && !r.b1) { r.b1 = true; Feedback.tick(); }

  if (restante <= 0 && !r.alerted) {
    r.alerted = true;
    Feedback.finish();
    bar.classList.add('over');
    setTimeout(() => { if (DB.active && DB.active.rest === r) { DB.active.rest = null; save(); render(); } }, 1200);
  }
}

function finalizarTreino() {
  const s = DB.active; if (!s) return;
  const feitas = sessionSetsDone(s);
  if (!feitas) {
    confirmDialog('Nenhuma série concluída', 'Você não marcou nenhuma série. Descartar este treino?', 'Descartar')
      .then(ok => { if (ok) { DB.active = null; save(); closeRoute(); toast('Treino descartado'); } });
    return;
  }
  s.endedAt = Date.now();
  s.rest = null;
  s.items = s.items.map(it => Object.assign({}, it, { sets: it.sets.filter(x => x.done) })).filter(it => it.sets.length);
  DB.sessions.push(s);
  DB.active = null;
  save();

  const vol = sessionVolume(s), dur = s.endedAt - s.startedAt;
  state.route = null; state.stack = []; state.tab = 'home';
  render();
  resumoTreino(s, vol, dur, feitas);
}

function resumoTreino(s, vol, dur, feitas) {
  const wrap = $('#modal');
  wrap.innerHTML = `<div class="modal-card resumo">
    <div class="resumo-badge"><svg viewBox="0 0 24 24"><path d="M4 12.5l5 5L20 6.5"/></svg></div>
    <h3>Treino concluído</h3>
    <p class="resumo-sub">Treino ${esc(s.letter)}${s.workoutName ? ' · ' + esc(s.workoutName) : ''}</p>
    <div class="resumo-grid">
      <div><span>${fmtDuration(dur)}</span><small>duração</small></div>
      <div><span>${feitas}</span><small>séries</small></div>
      <div><span>${Math.round(vol).toLocaleString('pt-BR')}</span><small>kg de volume</small></div>
    </div>
    <button class="btn btn-primary btn-block" data-mod="ok">Fechar</button>
  </div>`;
  wrap.classList.add('show');
  wrap.onclick = ev => {
    if (!ev.target.closest('[data-mod]') && ev.target !== wrap) return;
    wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
  };
}


/* ============================================================
   Progresso: números, frequência, gráfico e treinos realizados
   ============================================================ */

function viewProgresso() {
  const feitas = DB.sessions.filter(s => s.endedAt).sort((a,b) => b.endedAt - a.endedAt);

  let html = `
  <div class="topwrap curto">${headerBrand(false, 'Meu Progresso')}</div>
  <div class="body">`;

  if (!feitas.length) {
    html += `<div class="empty">
      <div class="empty-icon">
        <svg viewBox="0 0 24 24" class="ico-empty"><path d="M4 19h16M7 19v-6M12 19V6M17 19v-9"/></svg>
      </div>
      <h3>Sem treinos ainda</h3>
      <p>Quando você concluir o primeiro treino, sua evolução de carga aparece aqui.</p>
    </div></div>`;
    return html;
  }

  const volTotal = feitas.reduce((a,s) => a + sessionVolume(s), 0);
  const tempoTotal = feitas.reduce((a,s) => a + (s.endedAt - s.startedAt), 0);
  const agora = new Date();
  const mes = feitas.filter(s => {
    const d = new Date(s.endedAt);
    return d.getMonth() === agora.getMonth() && d.getFullYear() === agora.getFullYear();
  }).length;

  html += `
    <div class="stat-row">
      <div class="stat"><b>${mes}</b><small>treinos<br>este mês</small></div>
      <div class="stat"><b>${(volTotal/1000).toFixed(1).replace('.',',')}t</b><small>volume<br>acumulado</small></div>
      <div class="stat"><b>${Math.round(tempoTotal/3600000)}h</b><small>tempo<br>total</small></div>
    </div>

    <h3 class="section-title">Frequência</h3>
    <div class="card">${freqBars(feitas)}</div>`;

  const nomes = Array.from(new Set(
    feitas.flatMap(s => (s.items||[]).map(i => (i.name||'').trim())).filter(Boolean)
  )).sort((a,b) => a.localeCompare(b,'pt-BR'));

  if (nomes.length) {
    const sel = state.progressExercise && nomes.includes(state.progressExercise) ? state.progressExercise : nomes[0];
    html += `
      <h3 class="section-title">Progressão de carga</h3>
      <div class="card chart-card">
        <select class="input select" data-act="pick-progress">
          ${nomes.map(n => `<option value="${esc(n)}"${n===sel?' selected':''}>${esc(n)}</option>`).join('')}
        </select>
        <canvas id="chart" height="180"></canvas>
        <div class="chart-legend" id="chart-legend"></div>
      </div>`;
  }

  html += `<h3 class="section-title">Treinos realizados</h3>`;
  feitas.forEach(s => {
    const aberto = state.historyOpen === s.id;
    const vol = sessionVolume(s);
    html += `
      <div class="card sess-card${aberto ? ' aberta' : ''}">
        <div class="sess-head" data-act="toggle-sess" data-id="${s.id}">
          <div class="letra sm">${esc(s.letter || '?')}</div>
          <div class="tw-info">
            <h4>${esc(s.workoutName)}</h4>
            <p>${fmtBR(s.endedAt)} · ${fmtDuration(s.endedAt - s.startedAt)} · ${Math.round(vol).toLocaleString('pt-BR')} kg</p>
          </div>
          <svg class="chev${aberto ? ' up' : ''}" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg>
        </div>`;
    if (aberto) {
      html += `<div class="sess-detalhe">`;
      (s.items||[]).forEach(it => {
        html += `<div class="sess-ex"><b>${esc(it.name)}</b><span>${(it.sets||[])
          .map(x => `${num(x.reps)}×${x.load === '' || x.load == null ? '—' : num(x.load)+'kg'}`).join(' · ')}</span></div>`;
      });
      html += `<button class="btn btn-ghost btn-xs danger" data-act="del-sess" data-id="${s.id}">Excluir registro</button></div>`;
    }
    html += `</div>`;
  });

  html += `</div>`;
  return html;
}

function freqBars(feitas) {
  const semanas = [];
  const hoje = new Date(); hoje.setHours(0,0,0,0);
  const seg = new Date(hoje); seg.setDate(seg.getDate() - ((seg.getDay()+6)%7));
  for (let i = 11; i >= 0; i--) {
    const ini = new Date(seg); ini.setDate(ini.getDate() - i*7);
    const fim = new Date(ini); fim.setDate(fim.getDate()+7);
    semanas.push({ n: feitas.filter(s => s.endedAt >= ini.getTime() && s.endedAt < fim.getTime()).length, ini });
  }
  const max = Math.max(1, ...semanas.map(s => s.n));
  return `<div class="freq-graf">${semanas.map((s,i) => `
    <div class="fg-col">
      <div class="fg-bar" style="height:${Math.max(6, s.n/max*76)}px;opacity:${s.n?1:.22}">${s.n?`<span>${s.n}</span>`:''}</div>
      <small>${i%3===0||i===11 ? s.ini.getDate()+'/'+(s.ini.getMonth()+1) : ''}</small>
    </div>`).join('')}</div>
  <p class="freq-cap">Treinos por semana — últimas 12 semanas</p>`;
}

/* ---------- Gráfico de carga (canvas puro) ---------- */
function drawProgressChart() {
  const cv = document.getElementById('chart');
  if (!cv) return;

  let nomes;
  if (state.route && state.route.name === 'evolucao') {
    const a = acharFicha(state.route.w);
    nomes = a ? (a.ficha.items||[]).map(i => (i.name||'').trim()).filter(Boolean) : [];
  } else {
    nomes = Array.from(new Set(DB.sessions.filter(s => s.endedAt)
      .flatMap(s => (s.items||[]).map(i => (i.name||'').trim())).filter(Boolean)))
      .sort((a,b) => a.localeCompare(b,'pt-BR'));
  }
  const alvo = state.progressExercise && nomes.includes(state.progressExercise) ? state.progressExercise : nomes[0];
  if (!alvo) return;

  const pontos = DB.sessions.filter(s => s.endedAt).map(s => {
    const it = (s.items||[]).find(i => (i.name||'').trim().toLowerCase() === alvo.toLowerCase());
    if (!it) return null;
    const cargas = (it.sets||[]).map(x => num(x.load)).filter(v => v > 0);
    if (!cargas.length) return null;
    return { t: s.endedAt, v: Math.max.apply(null, cargas) };
  }).filter(Boolean).sort((a,b) => a.t - b.t);

  const legend = document.getElementById('chart-legend');
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth || 320, H = 180;
  cv.width = W*dpr; cv.height = H*dpr;
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);

  if (!pontos.length) {
    ctx.fillStyle = '#6C6C70';
    ctx.font = '13px -apple-system, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Sem carga registrada para este exercício', W/2, H/2);
    if (legend) legend.textContent = '';
    return;
  }

  const padL = 36, padR = 12, padT = 16, padB = 24;
  const vals = pontos.map(p => p.v);
  let min = Math.min.apply(null, vals), max = Math.max.apply(null, vals);
  if (min === max) { min = Math.max(0, min-5); max = max+5; }
  const span = max-min;
  min = Math.max(0, min - span*0.15); max = max + span*0.15;

  const X = i => pontos.length === 1 ? padL + (W-padL-padR)/2 : padL + (i/(pontos.length-1))*(W-padL-padR);
  const Y = v => padT + (1 - (v-min)/(max-min))*(H-padT-padB);

  ctx.strokeStyle = 'rgba(0,0,0,.08)';
  ctx.fillStyle = '#8E8E93';
  ctx.font = '10px -apple-system, system-ui, sans-serif';
  ctx.textAlign = 'right'; ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const v = min + (max-min)*(i/3);
    const y = Math.round(Y(v))+.5;
    ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(W-padR,y); ctx.stroke();
    ctx.fillText(Math.round(v)+'', padL-6, y+3);
  }

  const g = ctx.createLinearGradient(0,padT,0,H-padB);
  g.addColorStop(0,'rgba(0,0,0,.12)');
  g.addColorStop(1,'rgba(0,0,0,0)');
  ctx.beginPath();
  ctx.moveTo(X(0), Y(pontos[0].v));
  pontos.forEach((p,i) => ctx.lineTo(X(i), Y(p.v)));
  ctx.lineTo(X(pontos.length-1), H-padB);
  ctx.lineTo(X(0), H-padB);
  ctx.closePath(); ctx.fillStyle = g; ctx.fill();

  ctx.beginPath();
  pontos.forEach((p,i) => i ? ctx.lineTo(X(i),Y(p.v)) : ctx.moveTo(X(i),Y(p.v)));
  ctx.strokeStyle = '#000'; ctx.lineWidth = 2.5;
  ctx.lineJoin = 'round'; ctx.lineCap = 'round'; ctx.stroke();

  pontos.forEach((p,i) => {
    ctx.beginPath(); ctx.arc(X(i),Y(p.v),3.5,0,Math.PI*2);
    ctx.fillStyle = '#fff'; ctx.fill();
    ctx.strokeStyle = '#000'; ctx.lineWidth = 2; ctx.stroke();
  });

  ctx.fillStyle = '#8E8E93'; ctx.textAlign = 'left';
  ctx.fillText(fmtDate(pontos[0].t).split(', ').pop(), padL, H-7);
  if (pontos.length > 1) {
    ctx.textAlign = 'right';
    ctx.fillText(fmtDate(pontos[pontos.length-1].t).split(', ').pop(), W-padR, H-7);
  }

  if (legend) {
    const dif = pontos[pontos.length-1].v - pontos[0].v;
    legend.innerHTML = `<b>${fmtKg(pontos[pontos.length-1].v)}</b> máxima atual` +
      (pontos.length > 1 ? ` · <span class="${dif>=0?'up':'down'}">${dif>0?'+':''}${String(fmtKg(dif)).replace(' kg','')} kg</span> desde o início` : '');
  }
}


/* ============================================================
   Perfil: conta, preferências, importar/exportar, sair
   ============================================================ */

function viewPerfil() {
  const c = DB.account || {};
  const total = DB.routines.reduce((a,r) => a + (r.workouts||[]).length, 0);

  return `
  <div class="topwrap curto">
    ${headerBrand(false, null)}
    <div class="perfil-bloco">
      ${avatarHTML('grande')}
      <p class="perfil-nome">${esc(c.nome || '')}</p>
      <p class="perfil-email">${esc(c.email || '')}</p>
    </div>
  </div>
  <div class="body">

    <h3 class="section-title">Conta</h3>
    <div class="card">
      <label class="field-label">Nome</label>
      <input class="input" type="text" value="${esc(c.nome || '')}" data-c="nome">
      <label class="field-label">E-mail</label>
      <input class="input" type="email" inputmode="email" value="${esc(c.email || '')}" data-c="email">
      <label class="field-label">Peso corporal (kg)</label>
      <input class="input" type="number" inputmode="decimal" step="0.1" placeholder="Opcional"
             value="${DB.profile.weight == null ? '' : esc(DB.profile.weight)}" data-p="weight">
      <button class="btn btn-outline btn-block" data-act="trocar-senha">Alterar senha</button>
    </div>

    <h3 class="section-title">Treino</h3>
    <div class="card">
      <label class="field-label">Descanso padrão (segundos)</label>
      <input class="input" type="number" inputmode="numeric" step="5" value="${esc(DB.settings.restDefault)}" data-st="restDefault">
      <div class="switch-row">
        <span>Som no fim do descanso</span>
        <button class="switch${DB.settings.sound ? ' on' : ''}" data-act="flag" data-k="sound"><i></i></button>
      </div>
      <div class="switch-row">
        <span>Vibrar no fim do descanso</span>
        <button class="switch${DB.settings.vibrate ? ' on' : ''}" data-act="flag" data-k="vibrate"><i></i></button>
      </div>
    </div>

    <h3 class="section-title" id="importar">Rotinas do personal</h3>
    <div class="card">
      <p class="hint">Cole aqui o JSON da rotina que eu montar para você, ou escolha o arquivo <code>.json</code>.</p>
      <textarea class="input mono" rows="5" id="import-box" placeholder='{ "tipo": "treino-app/rotina", "rotina": { ... } }'></textarea>
      <button class="btn btn-primary btn-block" data-act="import-text">Importar do texto</button>
      <label class="btn btn-outline btn-block file-btn">
        Escolher arquivo .json
        <input type="file" accept=".json,application/json" id="import-file" hidden>
      </label>
    </div>

    <h3 class="section-title">Backup</h3>
    <div class="card">
      <p class="hint">O backup guarda conta, rotinas, histórico e preferências num arquivo só.</p>
      <button class="btn btn-outline btn-block" data-act="export-all">Exportar backup completo</button>
      <button class="btn btn-outline btn-block" data-act="export-rotinas">Exportar só as rotinas</button>
      <button class="btn btn-ghost btn-block danger" data-act="wipe">Apagar todos os dados</button>
    </div>

    <button class="btn btn-outline btn-block" data-act="sair">Sair da conta</button>

    <p class="version">Treino ${APP_VERSION} · ${DB.routines.length} rotinas · ${total} treinos · ${DB.sessions.length} execuções<br>
    ${Store.persistent ? 'Dados salvos neste aparelho.' : '⚠️ Este navegador está bloqueando o armazenamento — exporte backup com frequência.'}</p>
  </div>`;
}

function trocarSenha() {
  const wrap = $('#modal');
  wrap.innerHTML = `<div class="modal-card">
    <h3>Alterar senha</h3>
    ${DB.account && DB.account.hash ? `<input class="input" type="password" id="s-atual" placeholder="Senha atual">` : ''}
    <input class="input" type="password" id="s-nova" placeholder="Nova senha (mín. 6)">
    <input class="input" type="password" id="s-nova2" placeholder="Repita a nova senha">
    <div class="modal-actions">
      <button class="btn btn-ghost" data-mod="cancel">Cancelar</button>
      <button class="btn btn-primary" data-mod="ok">Salvar</button>
    </div></div>`;
  wrap.classList.add('show');
  wrap.onclick = ev => {
    const b = ev.target.closest('[data-mod]');
    if (!b) return;
    if (b.dataset.mod === 'ok') {
      const c = DB.account;
      if (c.hash) {
        const atual = ($('#s-atual') || {}).value || '';
        if (hashSenha(atual, c.salt) !== c.hash) return toast('Senha atual incorreta', 'err');
      }
      const a = $('#s-nova').value, b2 = $('#s-nova2').value;
      if (a.length < 6) return toast('Mínimo 6 caracteres', 'err');
      if (a !== b2) return toast('As senhas não são iguais', 'err');
      const salt = novoSalt();
      c.salt = salt; c.hash = hashSenha(a, salt);
      delete c.semSenha;
      save();
      toast('Senha alterada');
    }
    wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
  };
}

/* ------------------------------------------------------------
   Importação
   ------------------------------------------------------------ */
function normalizarTreino(t) {
  const brutos = t.exercicios || t.exercises || t.items || [];
  return {
    id: uid(),
    letter: String(t.letra || t.letter || '').toUpperCase().slice(0,1) || 'A',
    name: t.nome || t.name || '',
    note: t.obs || t.observacoes || t.note || '',
    items: brutos.map(e => ({
      id: uid(),
      name: e.nome || e.name || 'Exercício',
      sets: parseInt(e.series != null ? e.series : (e.sets != null ? e.sets : 3)) || 3,
      reps: String(e.reps != null ? e.reps : (e.repeticoes != null ? e.repeticoes : '10')),
      load: (e.carga != null && e.carga !== '') ? num(e.carga) : ((e.load != null && e.load !== '') ? num(e.load) : null),
      rest: parseInt(e.descanso != null ? e.descanso : (e.rest != null ? e.rest : DB.settings.restDefault)) || DB.settings.restDefault,
      note: e.obs || e.observacao || e.note || '',
      video: e.video || e.link || ''
    }))
  };
}

function parseData(v, fallback) {
  if (!v) return fallback;
  const t = Date.parse(String(v).length <= 10 ? v + 'T00:00:00' : v);
  return isNaN(t) ? fallback : t;
}

function normalizarRotina(r) {
  const treinos = r.treinos || r.fichas || r.workouts || [];
  const hoje = Date.now();
  const fim = new Date(); fim.setMonth(fim.getMonth() + 1);
  return {
    id: uid(),
    name: r.nome || r.name || 'Rotina importada',
    start: parseData(r.inicio || r.start, hoje),
    end: parseData(r.fim || r.end, fim.getTime()),
    goal: r.objetivo || r.goal || 'Hipertrofia',
    level: r.nivel || r.level || 'Iniciante',
    archived: false,
    workouts: treinos.map(normalizarTreino)
  };
}

function importarJSON(texto) {
  let data;
  try { data = JSON.parse(texto); }
  catch (e) { return toast('JSON inválido — confira se copiou o texto inteiro', 'err'); }

  /* backup completo */
  if (data.routines && data.sessions) {
    confirmDialog('Restaurar backup',
      'Isso substitui a conta, as rotinas e todo o histórico deste aparelho.', 'Restaurar')
      .then(ok => {
        if (!ok) return;
        DB = Object.assign(emptyDB(), data);
        DB.active = null;
        save(); toast('Backup restaurado'); go('home');
      });
    return;
  }

  /* uma ou várias rotinas */
  let rotinas = null;
  if (data.rotina) rotinas = [data.rotina];
  else if (Array.isArray(data.rotinas)) rotinas = data.rotinas;
  else if (Array.isArray(data.routines)) rotinas = data.routines;
  else if (data.fichas || data.treinos || Array.isArray(data)) {
    /* formato antigo: só fichas → vira uma rotina */
    const fichas = Array.isArray(data) ? data : (data.fichas || data.treinos);
    rotinas = [{ nome: data.nome || 'Rotina importada', treinos: fichas }];
  }

  if (!rotinas || !rotinas.length) return toast('Nenhuma rotina encontrada nesse arquivo', 'err');

  const novas = rotinas.map(normalizarRotina);
  novas.forEach(nr => {
    const igual = DB.routines.find(r => r.name.trim().toLowerCase() === nr.name.trim().toLowerCase());
    if (igual) {
      /* atualiza a rotina existente, preservando os ids dos treinos por letra
         para que o histórico continue ligado */
      igual.start = nr.start; igual.end = nr.end;
      igual.goal = nr.goal; igual.level = nr.level; igual.archived = false;
      igual.workouts = nr.workouts.map(nw => {
        const antigo = (igual.workouts || []).find(w => w.letter === nw.letter);
        return antigo ? Object.assign(nw, { id: antigo.id }) : nw;
      });
    } else {
      DB.routines.unshift(nr);
    }
  });
  save();
  state.rotinaAberta = (DB.routines[0] || {}).id;
  state.verArquivadas = false;
  toast(`${novas.length} rotina${novas.length > 1 ? 's' : ''} importada${novas.length > 1 ? 's' : ''}`);
  go('treinos');
}

/* ------------------------------------------------------------
   Exportação
   ------------------------------------------------------------ */
function baixarArquivo(nome, conteudo) {
  try {
    const blob = new Blob([conteudo], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = nome;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1500);
    toast('Arquivo gerado');
  } catch (e) {
    const wrap = $('#modal');
    wrap.innerHTML = `<div class="modal-card">
      <h3>Copie seu backup</h3>
      <textarea class="input mono" rows="8" readonly>${esc(conteudo)}</textarea>
      <div class="modal-actions"><button class="btn btn-primary" data-mod="ok">Fechar</button></div></div>`;
    wrap.classList.add('show');
    wrap.onclick = ev => {
      if (!ev.target.closest('[data-mod]')) return;
      wrap.classList.remove('show'); wrap.innerHTML = ''; wrap.onclick = null;
    };
  }
}

const stamp = () => { const d = new Date(); return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}`; };

function exportarTudo() {
  baixarArquivo(`treino-backup-${stamp()}.json`,
    JSON.stringify(Object.assign({ tipo: 'treino-app/backup', appVersion: APP_VERSION }, DB), null, 2));
}

function exportarRotinas() {
  const iso = ts => { const d = new Date(ts); return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}`; };
  baixarArquivo(`treino-rotinas-${stamp()}.json`, JSON.stringify({
    tipo: 'treino-app/rotinas',
    versao: 2,
    rotinas: DB.routines.map(r => ({
      nome: r.name, inicio: iso(r.start), fim: iso(r.end),
      objetivo: r.goal, nivel: r.level,
      treinos: (r.workouts||[]).map(w => ({
        letra: w.letter, nome: w.name, obs: w.note || '',
        exercicios: (w.items||[]).map(i => ({
          nome: i.name, series: i.sets, reps: i.reps,
          carga: i.load, descanso: i.rest, obs: i.note || '', video: i.video || ''
        }))
      }))
    }))
  }, null, 2));
}


/* ============================================================
   Renderização, eventos e inicialização
   ============================================================ */

function render() {
  const screen = $('#screen');
  const body = document.body;

  /* não logado → tela de entrada */
  if (!logado || !DB.account) {
    body.className = 'tela-auth';
    screen.innerHTML = viewAuth();
    return;
  }

  const rota = state.route ? state.route.name : null;
  body.className = rota === 'session' ? 'em-treino' : (rota ? 'sem-tabs' : '');

  if (rota === 'session') screen.innerHTML = viewSession();
  else if (rota === 'workout') screen.innerHTML = viewWorkout();
  else if (rota === 'editor') screen.innerHTML = viewEditor();
  else if (rota === 'evolucao') screen.innerHTML = viewEvolucao();
  else if (state.tab === 'home') screen.innerHTML = viewHome();
  else if (state.tab === 'treinos') screen.innerHTML = viewTreinos();
  else if (state.tab === 'progresso') screen.innerHTML = viewProgresso();
  else screen.innerHTML = viewPerfil();

  $$('#tabbar .tab').forEach(t => t.classList.toggle('on', t.dataset.tab === state.tab && !rota));
  moverPilula(!!pilula.style.width);

  if (rota === 'evolucao' || (!rota && state.tab === 'progresso')) drawProgressChart();
}

/* ------------------------------------------------------------
   Cliques
   ------------------------------------------------------------ */
document.addEventListener('click', async (ev) => {
  const tabBtn = ev.target.closest('#tabbar .tab');
  if (tabBtn) { Feedback.unlock(); go(tabBtn.dataset.tab); return; }

  const el = ev.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  Feedback.unlock();

  switch (act) {
    /* ---- autenticação ---- */
    case 'auth-mode':
      /* guarda o que já foi digitado antes de trocar de aba */
      state.authNome = campo('au-nome') || state.authNome || '';
      state.authEmail = campo('au-email') || state.authEmail || '';
      state.authMode = el.dataset.v;
      state.authErro = null;
      render();
      break;
    case 'auth-go': autenticar(); break;
    case 'esqueci': esqueciSenha(); break;
    case 'trocar-senha': trocarSenha(); break;
    case 'sair': {
      const ok = await confirmDialog('Sair da conta',
        'Seus treinos continuam salvos neste aparelho. Você vai precisar da senha para entrar de novo.', 'Sair', false);
      if (ok) { sair(); state.tab = 'home'; state.route = null; state.stack = []; state.authMode = 'login'; render(); }
      break;
    }

    /* ---- navegação ---- */
    case 'tab': go(el.dataset.v); break;
    case 'close-route': closeRoute(); break;
    case 'ir-importar':
      state.tab = 'perfil'; state.route = null; render();
      setTimeout(() => { const t = document.getElementById('importar'); if (t) t.scrollIntoView({ behavior: 'smooth' }); }, 60);
      break;

    /* ---- perfil ---- */
    case 'trocar-foto': trocarFoto(); break;
    case 'flag': DB.settings[el.dataset.k] = !DB.settings[el.dataset.k]; save(); render(); break;

    /* ---- rotinas ---- */
    case 'ver-rotinas': state.verArquivadas = el.dataset.v === '1'; state.rotinaAberta = null; render(); break;
    case 'abrir-rotina':
      state.rotinaAberta = state.rotinaAberta === el.dataset.r ? null : el.dataset.r;
      render();
      break;
    case 'nova-rotina': novaRotina(); break;
    case 'editar-rotina': editarRotina(el.dataset.r); break;
    case 'add-treino': addTreino(el.dataset.r); break;
    case 'arquivar':
    case 'desarquivar': {
      const r = DB.routines.find(x => x.id === el.dataset.r);
      if (r) { r.archived = act === 'arquivar'; save(); state.rotinaAberta = null; render(); toast(r.archived ? 'Rotina arquivada' : 'Rotina reativada'); }
      break;
    }
    case 'del-rotina': {
      const r = DB.routines.find(x => x.id === el.dataset.r);
      const ok = await confirmDialog('Excluir rotina',
        `"${r ? r.name : ''}" e seus treinos serão removidos. Seu histórico de execuções é mantido.`, 'Excluir');
      if (ok) { DB.routines = DB.routines.filter(x => x.id !== el.dataset.r); save(); state.rotinaAberta = null; render(); toast('Rotina excluída'); }
      break;
    }

    /* ---- treinos ---- */
    case 'ver-treino': openRoute({ name: 'workout', w: el.dataset.w }); break;
    case 'editar-treino': openRoute({ name: 'editor', w: el.dataset.w }); break;
    case 'evolucao': state.progressExercise = null; openRoute({ name: 'evolucao', w: el.dataset.w }); break;
    case 'ultimo-registro': { const it = itemAtivo(el.dataset.s); if (it) abrirUltimoRegistro(it.name, it.note); break; }
    case 'video-picker': abrirPickerVideo(el.dataset.w, el.dataset.i); break;
    case 'ver-video': { const it = itemAtivo(el.dataset.s); if (it) abrirVideoExercicio(it.name, it.video); break; }
    case 'del-treino': {
      const ok = await confirmDialog('Excluir treino', 'Este treino sai da rotina. O histórico é mantido.', 'Excluir');
      if (ok) {
        DB.routines.forEach(r => { r.workouts = (r.workouts || []).filter(w => w.id !== el.dataset.w); });
        save(); closeRoute(); toast('Treino excluído');
      }
      break;
    }
    case 'set-letter': {
      const a = acharFicha(el.dataset.w);
      if (a) { a.ficha.letter = el.dataset.v; save(); render(); }
      break;
    }
    case 'add-ex': {
      const a = acharFicha(el.dataset.w);
      if (a) { addExercicio(a.ficha); save(); render(); }
      break;
    }
    case 'del-ex': {
      const a = acharFicha(el.dataset.w);
      if (a) { a.ficha.items = (a.ficha.items || []).filter(i => i.id !== el.dataset.i); save(); render(); }
      break;
    }
    case 'move-up':
    case 'move-down': {
      const a = acharFicha(el.dataset.w);
      if (!a) break;
      const arr = a.ficha.items;
      const i = arr.findIndex(x => x.id === el.dataset.i);
      const j = act === 'move-up' ? i - 1 : i + 1;
      if (i < 0 || j < 0 || j >= arr.length) break;
      [arr[i], arr[j]] = [arr[j], arr[i]];
      save(); render();
      break;
    }

    /* ---- execução ---- */
    case 'start': iniciarTreino(el.dataset.w); break;
    case 'resume': openRoute({ name: 'session' }); break;
    case 'toggle-ex':
      if (DB.active) { DB.active.open = DB.active.open === el.dataset.i ? null : el.dataset.i; save(); render(); }
      break;
    case 'toggle-set': toggleSet(el.dataset.s, parseInt(el.dataset.si)); break;
    case 'add-set': addSet(el.dataset.s); break;
    case 'rm-set': rmSet(el.dataset.s); break;
    case 'rest-now': { const it = itemAtivo(el.dataset.s); if (it) { iniciarDescanso(it.rest); render(); } break; }
    case 'rest-add': ajustarDescanso(parseInt(el.dataset.v)); break;
    case 'rest-skip': pularDescanso(); break;
    case 'finish': finalizarTreino(); break;
    case 'discard': {
      const ok = await confirmDialog('Descartar treino', 'Tudo o que você marcou neste treino será perdido.', 'Descartar');
      if (ok) { DB.active = null; save(); closeRoute(); toast('Treino descartado'); }
      break;
    }

    /* ---- progresso ---- */
    case 'toggle-sess': state.historyOpen = state.historyOpen === el.dataset.id ? null : el.dataset.id; render(); break;
    case 'del-sess': {
      const ok = await confirmDialog('Excluir registro', 'Esse treino sai do histórico e dos gráficos.', 'Excluir');
      if (ok) { DB.sessions = DB.sessions.filter(s => s.id !== el.dataset.id); save(); render(); }
      break;
    }

    /* ---- dados ---- */
    case 'import-text': {
      const box = document.getElementById('import-box');
      if (box && box.value.trim()) importarJSON(box.value.trim());
      else toast('Cole o JSON no campo acima', 'err');
      break;
    }
    case 'export-all': exportarTudo(); break;
    case 'export-rotinas': exportarRotinas(); break;
    case 'wipe': {
      const ok = await confirmDialog('Apagar tudo',
        'Conta, rotinas, histórico e preferências serão apagados deste aparelho. Não dá para desfazer.', 'Apagar tudo');
      if (ok) { DB = emptyDB(); save(); sair(); render(); toast('Dados apagados'); }
      break;
    }
  }
});

/* ---- login/cadastro: Enter no teclado também confirma ----
   (não uso <form>+submit porque alguns visualizadores rodam a
   página em sandbox, onde o envio de formulário é bloqueado)   */
document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Enter') return;
  if (logado && DB.account) return;
  if (!ev.target.closest || !ev.target.closest('#auth-form')) return;
  ev.preventDefault();
  autenticar();
});

/* rede de segurança: se algum <form> escapar, não deixa navegar */
document.addEventListener('submit', (ev) => {
  ev.preventDefault();
  if (!logado || !DB.account) autenticar();
});

/* ---- campos de texto (sem re-render, para não perder o foco) ---- */
document.addEventListener('input', (ev) => {
  const t = ev.target;
  if (!t.matches || !t.matches('input, textarea')) return;

  if (t.dataset.w && t.dataset.i && t.dataset.f) {
    const a = acharFicha(t.dataset.w);
    const it = a && (a.ficha.items || []).find(x => x.id === t.dataset.i);
    if (it) {
      const f = t.dataset.f;
      it[f] = f === 'load' ? (t.value === '' ? null : num(t.value))
        : (f === 'sets' || f === 'rest') ? (parseInt(t.value) || '') : t.value;
      save();
    }
    return;
  }
  if (t.dataset.w && t.dataset.f) {
    const a = acharFicha(t.dataset.w);
    if (a) { a.ficha[t.dataset.f] = t.value; save(); }
    return;
  }
  if (t.dataset.s && t.dataset.si != null && t.dataset.f) {
    const it = itemAtivo(t.dataset.s);
    const st = it && it.sets[parseInt(t.dataset.si)];
    if (st) { st[t.dataset.f] = t.value; save(); }
    return;
  }
  if (t.dataset.c && DB.account) { DB.account[t.dataset.c] = t.value; save(); return; }
  if (t.dataset.p) { DB.profile[t.dataset.p] = t.value === '' ? null : num(t.value); save(); return; }
  if (t.dataset.st) { DB.settings[t.dataset.st] = parseInt(t.value) || 60; save(); }
});

document.addEventListener('change', (ev) => {
  const t = ev.target;
  if (t.matches('[data-act="pick-progress"]')) { state.progressExercise = t.value; drawProgressChart(); return; }
  if (t.id === 'import-file' && t.files && t.files[0]) {
    const fr = new FileReader();
    fr.onload = () => importarJSON(String(fr.result));
    fr.onerror = () => toast('Não consegui ler o arquivo', 'err');
    fr.readAsText(t.files[0]);
  }
});

/* ------------------------------------------------------------
   Tab bar: pílula da aba ativa vira lente ao arrastar (iOS 26)
   ------------------------------------------------------------ */
const barra = $('#tabbar'), pilula = $('#tabbar .tab-pill');
let arraste = null, ignorarClique = false;

function moverPilula(anima) {
  const on = $('#tabbar .tab.on');
  if (!on || !barra.offsetWidth) return;
  if (!anima) pilula.style.transition = 'none';
  pilula.style.width = on.offsetWidth + 'px';
  pilula.style.setProperty('--x', on.offsetLeft + 'px');
  if (!anima) { pilula.offsetWidth; pilula.style.transition = ''; }
}

function tabMaisPerto(x) {
  let melhor = null, dist = Infinity;
  $$('#tabbar .tab').forEach(t => {
    const r = t.getBoundingClientRect(), d = Math.abs(r.left + r.width / 2 - x);
    if (d < dist) { dist = d; melhor = t; }
  });
  return melhor;
}

/* centraliza a lente no dedo, presa dentro da barra */
function seguirDedo(x) {
  const tabs = $$('#tabbar .tab'), w = pilula.offsetWidth;
  const ini = tabs[0].offsetLeft, fim = tabs[tabs.length - 1].offsetLeft + tabs[tabs.length - 1].offsetWidth - w;
  const bx = barra.getBoundingClientRect().left + barra.clientLeft;
  pilula.style.setProperty('--x', Math.min(fim, Math.max(ini, x - bx - w / 2)) + 'px');
  const sob = tabMaisPerto(x);
  tabs.forEach(t => t.classList.toggle('sob', t === sob));
}

/* a cada quadro: segue o dedo e estica na horizontal conforme a velocidade */
function quadroArraste() {
  if (!arraste || !arraste.movido) return;
  const v = Math.abs(arraste.x - arraste.px); arraste.px = arraste.x;
  arraste.st += (1 + Math.min(.3, v / 40) - arraste.st) * .3;
  pilula.style.setProperty('--st', arraste.st.toFixed(3));
  seguirDedo(arraste.x);
  requestAnimationFrame(quadroArraste);
}

barra.addEventListener('pointerdown', (ev) => {
  if (ev.button || arraste || !$('#tabbar .tab.on')) return;
  ignorarClique = false;
  arraste = { id: ev.pointerId, x0: ev.clientX, x: ev.clientX, px: ev.clientX, st: 1, movido: false };
  pilula.classList.add('lens');
  seguirDedo(ev.clientX);
});
barra.addEventListener('pointermove', (ev) => {
  if (!arraste || ev.pointerId !== arraste.id) return;
  arraste.x = ev.clientX;
  if (!arraste.movido && Math.abs(arraste.x - arraste.x0) > 8) {
    arraste.movido = true;
    barra.classList.add('arrastando');
    try { barra.setPointerCapture(ev.pointerId); } catch (e) {}
    requestAnimationFrame(quadroArraste);
  }
});
function soltarArraste(ev) {
  if (!arraste || ev.pointerId !== arraste.id) return;
  const a = arraste; arraste = null;
  barra.classList.remove('arrastando');
  pilula.classList.remove('lens');
  pilula.style.removeProperty('--st');
  $$('#tabbar .tab.sob').forEach(t => t.classList.remove('sob'));
  if (a.movido && ev.type === 'pointerup') {
    /* arrastou: navega aqui e ignora o clique que vem depois */
    ignorarClique = true;
    Feedback.unlock(); go(tabMaisPerto(a.x).dataset.tab);
  } else moverPilula(true);   // toque simples: o clique navega
}
barra.addEventListener('pointerup', soltarArraste);
barra.addEventListener('pointercancel', soltarArraste);
barra.addEventListener('click', (ev) => {
  if (ignorarClique) { ignorarClique = false; ev.stopPropagation(); }
}, true);

/* ------------------------------------------------------------
   Ciclo de vida
   ------------------------------------------------------------ */
setInterval(tickTimers, 250);
document.addEventListener('visibilitychange', () => { if (!document.hidden) render(); });
window.addEventListener('resize', () => {
  moverPilula(false);
  if (state.route && state.route.name === 'evolucao') drawProgressChart();
  else if (!state.route && state.tab === 'progresso') drawProgressChart();
});

let wakeLock = null;
async function manterTelaLigada(ativar) {
  try {
    if (ativar && 'wakeLock' in navigator && !wakeLock) {
      wakeLock = await navigator.wakeLock.request('screen');
      wakeLock.addEventListener('release', () => { wakeLock = null; });
    } else if (!ativar && wakeLock) { await wakeLock.release(); wakeLock = null; }
  } catch (e) {}
}
setInterval(() => manterTelaLigada(!!(DB.active && state.route && state.route.name === 'session')), 4000);

try {
  if (location.protocol !== 'file:' && navigator.serviceWorker) {
    window.addEventListener('load', () => {
      try { navigator.serviceWorker.register('./sw.js').catch(() => {}); } catch (e) {}
    });
  }
} catch (e) { /* contexto em sandbox — segue sem service worker */ }

if (logado && DB.active) state.route = { name: 'session' };
render();
