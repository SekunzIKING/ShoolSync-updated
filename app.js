const API = (location.hostname === 'localhost') ? 'http://localhost:4000/api' : '/api';

let token = null;
let currentUser = null;

// safe load from localStorage
try {
  token = localStorage.getItem('kda_token') || null;
  const raw = localStorage.getItem('kda_user');
  currentUser = raw ? JSON.parse(raw) : null;
} catch (e) {
  token = null;
  currentUser = null;
}

// helpers
const qs = id => document.getElementById(id);
const setText = (el, v) => { if (!el) return; el.textContent = (v === null || v === undefined) ? '' : v; };
const safeVal = v => (v === null || v === undefined) ? '' : v;

function saveAuth(userObj, jwt) {
  currentUser = userObj || null;
  token = jwt || null;
  if (token) localStorage.setItem('kda_token', token); else localStorage.removeItem('kda_token');
  if (currentUser) localStorage.setItem('kda_user', JSON.stringify(currentUser)); else localStorage.removeItem('kda_user');
}
function clearAuth() {
  token = null; currentUser = null;
  localStorage.removeItem('kda_token'); localStorage.removeItem('kda_user');
}
function redirectToLogin(){ clearAuth(); location.href = 'index.html'; }

async function apiFetch(path, opts = {}) {
  opts.headers = opts.headers || {};
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (opts.body && !(opts.body instanceof FormData)) opts.headers['Content-Type'] = 'application/json';
  const res = await fetch(API + path, opts);
  const text = await res.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch(e) { body = text; }
  return { ok: res.ok, status: res.status, body };
}

// LOGIN page logic
if (location.pathname.endsWith('index.html') || location.pathname === '/' || location.pathname.endsWith('/')) {
  const btnLogin = qs('btnLogin');
  const emailEl = qs('loginEmail'), pwEl = qs('loginPassword');

  // if already authenticated, redirect based on role
  (async function autoRedirectIfAuth(){
    if (token) {
      // try to refresh currentUser if missing
      if (!currentUser) {
        const me = await apiFetch('/me');
        if (me.ok && me.body && me.body.user) {
          saveAuth(me.body.user, token);
        } else { clearAuth(); return; }
      }
      location.href = (currentUser && currentUser.role === 'admin') ? 'admin.html' : 'student.html';
    }
  })();

  if (btnLogin) {
    btnLogin.addEventListener('click', async () => {
      const email = (emailEl && emailEl.value || '').trim();
      const pw = (pwEl && pwEl.value) || '';
      if (!email || !pw) { alert('Enter credentials'); return; }
      const r = await apiFetch('/auth/login', { method: 'POST', body: JSON.stringify({ email, password: pw }) });
      if (!r.ok) { alert(r.body?.error || JSON.stringify(r.body)); return; }
      saveAuth(r.body.user || null, r.body.token || null);
      location.href = (currentUser && currentUser.role === 'admin') ? 'admin.html' : 'student.html';
    });
  }
}

// REGISTER page logic
if (location.pathname.endsWith('register.html')) {
  const btnRegister = qs('btnRegister');
  if (btnRegister) {
    btnRegister.addEventListener('click', async () => {
      const name = (qs('regName')?.value || '').trim();
      const email = (qs('regEmail')?.value || '').trim();
      const pw = (qs('regPassword')?.value || '');
      const role = (qs('regRole')?.value || 'student');
      if (!name || !email || pw.length < 6) { alert('Enter valid name, email and password (6+)'); return; }
      const r = await apiFetch('/auth/register', { method: 'POST', body: JSON.stringify({ name, email, password: pw, role }) });
      if (!r.ok) { alert(r.body?.error || JSON.stringify(r.body)); return; }
      saveAuth(r.body.user || null, r.body.token || null);
      location.href = (currentUser && currentUser.role === 'admin') ? 'admin.html' : 'student.html';
    });
  }
}

// common logout wiring for any page
const globalLogoutEl = qs('btnLogout');
if (globalLogoutEl) globalLogoutEl.addEventListener('click', () => redirectToLogin());

// UTIL: load current user from /api/me if token present but no user object
async function ensureCurrentUser() {
  if (token && !currentUser) {
    const res = await apiFetch('/me');
    if (res.ok && res.body && res.body.user) {
      saveAuth(res.body.user, token);
    } else {
      clearAuth();
      return false;
    }
  }
  return !!currentUser;
}

// ADMIN page init
if (location.pathname.endsWith('admin.html')) {
  (async function initAdmin(){
    if (!token) return redirectToLogin();
    const ok = await ensureCurrentUser(); if (!ok) return redirectToLogin();

    // navigation buttons
    const navBtns = Array.from(document.querySelectorAll('.nav button[data-screen]'));
    function setActive(screen){
      navBtns.forEach(b => b.classList.toggle('active', b.dataset.screen === screen));
      document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
      const el = qs(screen); if (el) el.classList.remove('hidden');
    }
    navBtns.forEach(b => b.addEventListener('click', () => setActive(b.dataset.screen)));
    // show profile name if present
    const profileEl = qs('profileName'); if (profileEl) setText(profileEl, safeVal(currentUser?.name || ''));

    // dashboard counts
    async function loadDashboard(){
      const [s,b,a] = await Promise.all([apiFetch('/students'), apiFetch('/books'), apiFetch('/attendance')]);
      qs('statStudents') && setText(qs('statStudents'), (s.ok && Array.isArray(s.body)) ? s.body.length : 0);
      qs('statBooks') && setText(qs('statBooks'), (b.ok && Array.isArray(b.body)) ? b.body.length : 0);
      qs('statAttendance') && setText(qs('statAttendance'), (a.ok && Array.isArray(a.body)) ? a.body.length : 0);
      qs('dashboardStats') && setText(qs('dashboardStats'), `Students: ${qs('statStudents')?.textContent || 0} • Books: ${qs('statBooks')?.textContent || 0} • Attendance: ${qs('statAttendance')?.textContent || 0}`);
    }

    // Students
    qs('studentForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fullName = (qs('studentName')?.value || '').trim();
      const classLevel = (qs('studentClass')?.value || '').trim();
      const parentPhone = (qs('studentPhone')?.value || '').trim();
      if (!fullName || !classLevel) { alert('Name and class required'); return; }
      const res = await apiFetch('/students', { method: 'POST', body: JSON.stringify({ fullName, classLevel, parentPhone }) });
      if (!res.ok) { alert(res.body?.error || JSON.stringify(res.body)); return; }
      qs('studentForm').reset();
      await loadStudents(); await loadDashboard();
    });

    async function loadStudents(){
      const r = await apiFetch('/students');
      const list = qs('studentsList'); const sel = qs('attStudent');
      if (list) list.innerHTML = '';
      if (sel) sel.innerHTML = '';
      if (!r.ok) { if (list) list.innerHTML = '<li class="muted">Failed to load</li>'; return; }
      r.body.forEach(s => {
        const li = document.createElement('li'); li.className = 'item';
        li.innerHTML = `<div><strong>${safeVal(s.fullName) || '—'}</strong><div class="muted">${safeVal(s.classLevel) || '—'}${s.parentPhone ? ' • ' + safeVal(s.parentPhone) : ''}</div></div>`;
        const del = document.createElement('button'); del.className='btn ghost'; del.textContent='Delete';
        del.onclick = async () => { if (!confirm('Delete student?')) return; const res = await apiFetch('/students/' + s._id, { method: 'DELETE' }); if (!res.ok) alert(res.body?.error || 'Delete failed'); await loadStudents(); await loadDashboard(); };
        li.appendChild(del);
        list.appendChild(li);
        if (sel) { const opt = document.createElement('option'); opt.value = s._id; opt.textContent = s.fullName; sel.appendChild(opt); }
      });
    }

    // Books
    qs('bookForm')?.addEventListener('submit', async e => {
      e.preventDefault();
      const title = (qs('bookTitle')?.value || '').trim();
      const author = (qs('bookAuthor')?.value || '').trim();
      if (!title) { alert('Title required'); return; }
      const r = await apiFetch('/books', { method: 'POST', body: JSON.stringify({ title, author }) });
      if (!r.ok) { alert(r.body?.error || JSON.stringify(r.body)); return; }
      qs('bookForm').reset(); await loadBooks(); await loadDashboard();
    });
    async function loadBooks(){
      const r = await apiFetch('/books');
      const list = qs('booksList'); if (list) list.innerHTML = '';
      if (!r.ok) { if(list) list.innerHTML = '<li class="muted">Failed to load</li>'; return; }
      r.body.forEach(b => {
        const li = document.createElement('li'); li.className='item';
        li.innerHTML = `<div><strong>${safeVal(b.title)}</strong><div class="muted">${safeVal(b.author)}</div></div>`;
        const del = document.createElement('button'); del.className='btn ghost'; del.textContent='Delete';
        del.onclick = async ()=>{ if(!confirm('Delete book?')) return; await apiFetch('/books/'+b._id,{ method:'DELETE' }); await loadBooks(); await loadDashboard(); };
        li.appendChild(del); list.appendChild(li);
      });
    }

    // Attendance
    qs('attendanceForm')?.addEventListener('submit', async e => {
      e.preventDefault();
      const studentId = qs('attStudent')?.value;
      const date = qs('attDate')?.value;
      const status = qs('attStatus')?.value;
      if (!studentId || !date) { alert('Select student and date'); return; }
      const r = await apiFetch('/attendance', { method: 'POST', body: JSON.stringify({ studentId, date, status }) });
      if (!r.ok) { alert(r.body?.error || JSON.stringify(r.body)); return; }
      qs('attendanceForm').reset(); await loadAttendance(); await loadDashboard();
    });
    async function loadAttendance(){
      const r = await apiFetch('/attendance');
      const list = qs('attendanceList'); if (list) list.innerHTML = '';
      if (!r.ok) { if(list) list.innerHTML = '<li class="muted">Failed to load</li>'; return; }
      r.body.forEach(a => {
        const name = a.studentId ? safeVal(a.studentId.fullName) : 'Unknown';
        const li = document.createElement('li'); li.className='item';
        li.innerHTML = `<div><strong>${name}</strong><div class="muted">${new Date(a.date).toLocaleDateString()} • ${safeVal(a.status)}</div></div>`;
        list.appendChild(li);
      });
    }

    // init
    setActive('dashboard');
    await loadDashboard(); await loadStudents(); await loadBooks(); await loadAttendance();
  })();
}

// STUDENT page init (read-only)
if (location.pathname.endsWith('student.html')) {
  (async function initStudent(){
    if (!token) return redirectToLogin();
    const ok = await ensureCurrentUser(); if (!ok) return redirectToLogin();

    // profile
    setText(qs('profileName'), safeVal(currentUser?.name || 'Student'));
    qs('btnLogout')?.addEventListener('click', () => redirectToLogin());

    // load books
    const b = await apiFetch('/books');
    const booksList = qs('booksList');
    if (booksList) {
      booksList.innerHTML = '';
      if (!b.ok) booksList.innerHTML = '<li class="muted">Failed to load books</li>';
      else b.body.forEach(book => {
        const li = document.createElement('li'); li.className='item';
        li.innerHTML = `<div><strong>${safeVal(book.title)}</strong><div class="muted">${safeVal(book.author)}</div></div>`;
        booksList.appendChild(li);
      });
    }

    // attendance: try to match student record by name, else show all
    const students = await apiFetch('/students');
    let studentId = null;
    if (students.ok && currentUser) {
      const match = students.body.find(s => s.fullName && currentUser && s.fullName.toLowerCase() === currentUser.name.toLowerCase());
      if (match) studentId = match._id;
    }
    const a = await apiFetch('/attendance');
    const attendanceList = qs('attendanceList');
    if (attendanceList) {
      attendanceList.innerHTML = '';
      if (!a.ok) attendanceList.innerHTML = '<li class="muted">Failed to load attendance</li>';
      else {
        const items = a.body.filter(rec => (studentId ? (rec.studentId && rec.studentId._id === studentId) : true));
        items.forEach(rec => {
          const name = rec.studentId ? safeVal(rec.studentId.fullName) : 'Unknown';
          const li = document.createElement('li'); li.className='item';
          li.innerHTML = `<div><strong>${name}</strong><div class="muted">${new Date(rec.date).toLocaleDateString()} • ${safeVal(rec.status)}</div></div>`;
          attendanceList.appendChild(li);
        });
        if (items.length === 0) attendanceList.innerHTML = '<li class="muted">No records available</li>';
      }
    }
  })();
}
