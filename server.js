import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import multer from 'multer';
import XLSX from 'xlsx';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import connectPgSimple from 'connect-pg-simple';
import { initDB, getDB, getPool, transaction } from './database.js';
import { decryptPassword, encryptPassword, generatePassword, hashPassword, isValidPassword, verifyPassword } from './security.js';
import { dayOfWeekFromDateOnly } from './date-utils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 4 * 1024 * 1024 } });
const vaultKeyPath = path.join(__dirname, '.teacher-password-vault.key');
let passwordVaultKey;
if (process.env.TEACHER_PASSWORD_VAULT_KEY) {
  passwordVaultKey = Buffer.from(process.env.TEACHER_PASSWORD_VAULT_KEY, 'base64');
  if (passwordVaultKey.length !== 32) throw new Error('TEACHER_PASSWORD_VAULT_KEY must be a base64-encoded 32-byte key');
} else if (process.env.NODE_ENV === 'production') {
  throw new Error('TEACHER_PASSWORD_VAULT_KEY is required in production');
} else if (fs.existsSync(vaultKeyPath)) {
  passwordVaultKey = Buffer.from(fs.readFileSync(vaultKeyPath, 'utf8').trim(), 'base64');
} else {
  passwordVaultKey = crypto.randomBytes(32);
  fs.writeFileSync(vaultKeyPath, passwordVaultKey.toString('base64'), { mode: 0o600 });
}
if (passwordVaultKey.length !== 32) throw new Error('Teacher password vault key must be 32 bytes');

const sessionSecretPath = path.join(__dirname, '.session-secret');
let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret && process.env.NODE_ENV === 'production') throw new Error('SESSION_SECRET is required in production');
if (!sessionSecret && fs.existsSync(sessionSecretPath)) sessionSecret = fs.readFileSync(sessionSecretPath, 'utf8').trim();
if (!sessionSecret) {
  sessionSecret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(sessionSecretPath, sessionSecret, { mode: 0o600 });
}

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
const PgSession = connectPgSimple(session);
app.use(session({
  name: 'spmi.sid',
  store: new PgSession({ pool: getPool(), tableName: 'user_sessions', createTableIfMissing: false }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}

function requireRole(...roles) {
  return async (req, res, next) => {
    if (!req.session.user) return res.redirect('/');
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).redirect('/');
    }
    if (req.session.user.role !== 'admin') {
      const db = getDB();
      const system = await db.one(`SELECT setting_value FROM system_settings WHERE setting_key = 'system_enabled'`) || { setting_value: '1' };
      if (system.setting_value !== '1') {
        req.session.destroy();
        return res.status(503).json({ success: false, message: 'Система временно отключена администратором' });
      }
      const account = await db.one(`SELECT account_enabled FROM users WHERE id = ?`, [req.session.user.id]);
      if (!account || account.account_enabled !== 1) {
        req.session.destroy();
        return res.status(403).json({ success: false, message: 'Для этого логина нет доступа' });
      }
    }
    next();
  };
}

function classifyStaffRole(title, position) {
  const text = `${title || ''} ${position || ''}`.toLowerCase();
  const isAcademic = text.includes('кандидат') || text.includes('доктор');
  const isWorkerPosition = text.includes('главный специалист') || text.includes('инженер');
  return isAcademic || !isWorkerPosition ? 'teacher' : 'worker';
}

function transliterateLogin(value) {
  const letters = {
    а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z', и: 'i', й: 'i',
    к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f',
    х: 'kh', ц: 'ts', ч: 'ch', ш: 'sh', щ: 'shch', ы: 'y', э: 'e', ю: 'yu', я: 'ya', ъ: '', ь: ''
  };
  return String(value || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .split('').map(char => letters[char] ?? char).join('').replace(/[^a-z0-9]/g, '');
}

function staffLoginBase(fullName) {
  const parts = String(fullName || '').trim().split(/\s+/).filter(Boolean);
  const surname = transliterateLogin(parts[0]) || 'staff';
  const initials = parts.slice(1, 3).map(part => transliterateLogin(part).charAt(0)).join('');
  return initials ? `${surname}_${initials}` : surname;
}

async function uniqueStaffLogin(db, fullName, excludeId = null) {
  const base = staffLoginBase(fullName);
  let login = base;
  let suffix = 2;
  while (true) {
    const exists = await db.exists(`SELECT id FROM users WHERE LOWER(login) = LOWER(?)${excludeId ? ' AND id != ?' : ''}`, excludeId ? [login, excludeId] : [login]);
    if (!exists) return login;
    login = `${base}_${suffix++}`;
  }
}

function normalizeExcelHeader(value) {
  return String(value || '').trim().toLowerCase().replace(/ё/g, 'е').replace(/[^a-zа-я0-9]/g, '');
}

function excelValue(row, aliases) {
  const values = new Map(Object.entries(row).map(([key, value]) => [normalizeExcelHeader(key), value]));
  for (const alias of aliases) {
    const key = normalizeExcelHeader(alias);
    if (values.has(key)) return values.get(key);
  }
  return '';
}

function studentRowsFromSheet(sheet) {
  const matrix = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
  const headerRow = matrix.slice(0, 25).findIndex((row) => {
    const headers = row.map(normalizeExcelHeader);
    return headers.includes('фио') && (headers.includes('шифр') || headers.includes('имягруппы') || headers.includes('группа'));
  });
  if (headerRow < 0) {
    throw new Error('Не найдена строка заголовков. В таблице должны быть столбцы «ФИО» и «Шифр» или «Имя группы»');
  }
  return XLSX.utils.sheet_to_json(sheet, { range: headerRow, defval: '' });
}

async function uniqueStudentLogin(db, fullName, code) {
  const normalizedCode = transliterateLogin(code);
  const nameBase = staffLoginBase(fullName);
  const base = normalizedCode ? (normalizedCode.startsWith('s') ? normalizedCode : `s${normalizedCode}`) : `student_${nameBase}`;
  let login = base;
  let suffix = 2;
  while (true) {
    const exists = await db.exists('SELECT id FROM users WHERE LOWER(login) = LOWER(?)', [login]);
    if (!exists) return login;
    login = `${base}_${suffix++}`;
  }
}

async function start() {
  await initDB();
  const db = getDB();

  const loginAttempts = new Map();
  const passwordRecoveryAttempts = new Map();
  const LOGIN_WINDOW_MS = 15 * 60 * 1000;
  const LOGIN_MAX_ATTEMPTS = 5;

  function teacherIsEvaluator(teacherId, programId) {
    return db.exists(`SELECT 1 FROM dpk_program_evaluators WHERE teacher_id = ? AND program_id = ?`, [teacherId, programId]);
  }

  function teacherHasProgramGroup(teacherId, programId, groupName) {
    return db.exists(`SELECT 1 FROM dpk_program_teachers WHERE teacher_id = ? AND program_id = ? AND group_name = ?`, [teacherId, programId, groupName]);
  }

  app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) {
      return res.json({ success: false, message: 'Заполните все поля' });
    }

    const attemptKey = `${req.ip}:${String(login).toLowerCase()}`;
    const now = Date.now();
    const attempt = loginAttempts.get(attemptKey);
    if (attempt && attempt.resetAt > now && attempt.count >= LOGIN_MAX_ATTEMPTS) {
      return res.status(429).json({ success: false, message: 'Слишком много попыток. Повторите через 15 минут' });
    }
    if (attempt && attempt.resetAt <= now) loginAttempts.delete(attemptKey);

    const recordFailure = () => {
      const current = loginAttempts.get(attemptKey);
      loginAttempts.set(attemptKey, current && current.resetAt > now ? { ...current, count: current.count + 1 } : { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    };

    const admin = await db.one('SELECT * FROM admin_accounts WHERE login = ?', [login]);
    if (admin && verifyPassword(password, admin.password)) {
      if (admin.account_enabled !== 1) return res.json({ success: false, message: 'Для этого логина нет доступа' });
      loginAttempts.delete(attemptKey);
      req.session.user = { id: admin.id, login: admin.login, role: 'admin', full_name: admin.full_name };
      return res.json({ success: true, redirect: '/dashboard/admin.html' });
    }

    const system = await db.one(`SELECT setting_value FROM system_settings WHERE setting_key = 'system_enabled'`) || { setting_value: '1' };
    if (system.setting_value !== '1') {
      return res.json({ success: false, message: 'Система временно отключена администратором' });
    }

    const user = await db.one('SELECT * FROM users WHERE login = ?', [login]);

    if (!user || !verifyPassword(password, user.password)) {
      recordFailure();
      return res.json({ success: false, message: 'Неверный логин или пароль' });
    }
    if (user.account_enabled !== 1) {
      return res.json({ success: false, message: 'Для этого логина нет доступа' });
    }

    const hasDeveloperAccess = user.developer_access === 1 && ['teacher', 'worker'].includes(user.role);
    req.session.user = {
      id: user.id,
      login: user.login,
      role: hasDeveloperAccess ? 'supervisor' : user.role,
      base_role: user.role,
      developer_access: hasDeveloperAccess ? 1 : 0,
      full_name: user.full_name,
      code: user.code,
      faculty: user.faculty,
      group_name: user.group_name,
      department: user.department,
      position: user.position,
      specialty: user.specialty
    };
    loginAttempts.delete(attemptKey);

    const routes = {
      student: '/dashboard/student.html',
      teacher: '/dashboard/teacher.html',
      worker: '/dashboard/worker.html',
      supervisor: '/dashboard/supervisor.html'
    };

    res.json({ success: true, redirect: hasDeveloperAccess ? routes.supervisor : routes[user.role] });
  });

  app.post('/api/password-recovery', async (req, res) => {
    const role = String(req.body.role || '').trim();
    const fullName = String(req.body.full_name || '').trim();
    const login = String(req.body.login || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!['student', 'teacher', 'worker'].includes(role) || !fullName || !login || !email) {
      return res.status(400).json({ success: false, message: 'Заполните все поля' });
    }
    if (fullName.length > 160 || login.length > 100 || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Проверьте введенные данные' });
    }

    const now = Date.now();
    const attemptKey = req.ip;
    const attempt = passwordRecoveryAttempts.get(attemptKey);
    if (attempt && attempt.resetAt > now && attempt.count >= 5) {
      return res.status(429).json({ success: false, message: 'Слишком много заявок. Повторите позже' });
    }
    passwordRecoveryAttempts.set(attemptKey, attempt && attempt.resetAt > now ? { ...attempt, count: attempt.count + 1 } : { count: 1, resetAt: now + 60 * 60 * 1000 });

    const account = await db.one(`SELECT id, full_name FROM users WHERE role = ? AND LOWER(login) = LOWER(?) LIMIT 1`, [role, login]);
    const normalizedName = value => String(value || '').trim().replace(/\s+/g, ' ').toLowerCase();
    const namesMatch = account && normalizedName(account.full_name) === normalizedName(fullName);
    const userId = namesMatch ? account.id : null;

    const existing = await db.one(`SELECT id FROM password_recovery_requests WHERE LOWER(login) = LOWER(?) AND email = ? AND status != 'resolved' LIMIT 1`, [login, email]);
    if (existing) {
      await db.run(`UPDATE password_recovery_requests SET role = ?, full_name = ?, user_id = ?, status = 'pending', created_at = CURRENT_TIMESTAMP WHERE id = ?`, [role, fullName, userId, existing.id]);
    } else {
      await db.run(`INSERT INTO password_recovery_requests (role, full_name, login, email, user_id) VALUES (?, ?, ?, ?, ?)`, [role, fullName, login, email, userId]);
    }
    res.json({ success: true, message: 'Заявка отправлена администратору' });
  });

  app.get('/api/admin/accounts', requireRole('admin'), async (req, res) => {
    const rows = await db.all(`SELECT id, login, role, full_name, group_name, department, developer_access, account_enabled, CASE WHEN password_vault IS NOT NULL THEN 1 ELSE 0 END AS password_available FROM users ORDER BY role, full_name`);
    res.json(rows);
  });

  app.get('/api/admin/password-recovery', requireRole('admin'), async (req, res) => {
    const rows = await db.all(`
      SELECT pr.*, u.id AS account_id, u.full_name AS account_name
      FROM password_recovery_requests pr
      LEFT JOIN users u ON u.id = pr.user_id
      WHERE pr.status != 'resolved'
      ORDER BY CASE pr.status WHEN 'pending' THEN 0 ELSE 1 END, pr.created_at DESC
    `);
    res.json(rows);
  });

  app.post('/api/admin/password-recovery/:id/reset', requireRole('admin'), async (req, res) => {
    const request = await db.one(`
      SELECT pr.*, u.id AS account_id, u.login AS account_login, u.full_name AS account_name
      FROM password_recovery_requests pr
      LEFT JOIN users u ON u.id = pr.user_id
      WHERE pr.id = ? AND pr.status != 'resolved'
      LIMIT 1
    `, [req.params.id]);
    if (!request) return res.status(404).json({ success: false, message: 'Заявка не найдена' });
    if (!request.account_id) return res.status(404).json({ success: false, message: 'Учетная запись не найдена. Проверьте логин и роль' });
    const generatedPassword = generatePassword();
    await transaction(async tx => {
      await tx.run(`UPDATE users SET password = ?, password_vault = ? WHERE id = ?`, [hashPassword(generatedPassword), encryptPassword(generatedPassword, passwordVaultKey), request.account_id]);
      await tx.run(`UPDATE password_recovery_requests SET user_id = ?, status = 'ready' WHERE id = ?`, [request.account_id, request.id]);
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, password: generatedPassword, email: request.email, login: request.account_login, full_name: request.account_name });
  });

  app.get('/api/admin/password-recovery/:id/password', requireRole('admin'), async (req, res) => {
    const request = await db.one(`SELECT pr.email, pr.status, u.login, u.full_name, u.password_vault FROM password_recovery_requests pr JOIN users u ON u.id = pr.user_id WHERE pr.id = ? AND pr.status = 'ready'`, [req.params.id]);
    if (!request?.password_vault) return res.status(404).json({ success: false, message: 'Пароль для отправки недоступен' });
    try {
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, password: decryptPassword(request.password_vault, passwordVaultKey), email: request.email, login: request.login, full_name: request.full_name });
    } catch {
      res.status(500).json({ success: false, message: 'Не удалось получить пароль' });
    }
  });

  app.put('/api/admin/password-recovery/:id/resolve', requireRole('admin'), async (req, res) => {
    await db.run(`UPDATE password_recovery_requests SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP WHERE id = ?`, [req.params.id]);
    res.json({ success: true });
  });

  app.post('/api/admin/accounts', requireRole('admin'), async (req, res) => {
    let { login, password, role, full_name, account_enabled = 1, developer_access = 0 } = req.body;
    const roles = ['student', 'teacher', 'worker', 'supervisor'];
    if ((!login && !['teacher', 'worker'].includes(role)) || (!password && role !== 'teacher') || !full_name || !roles.includes(role)) {
      return res.status(400).json({ success: false, message: 'Заполните обязательные поля' });
    }
    if (password && !/^[A-Za-z0-9]{8,9}$/.test(password)) return res.status(400).json({ success: false, message: 'Пароль должен содержать 8–9 латинских букв или цифр' });
    try {
      if (['teacher', 'worker'].includes(role)) login = await uniqueStaffLogin(db, full_name);
      const generatedPassword = role === 'teacher' ? generatePassword() : null;
      const accountPassword = generatedPassword || password;
      const hasDeveloperAccess = ['teacher', 'worker'].includes(role) && (developer_access === true || developer_access === 1) ? 1 : 0;
      await db.run(`INSERT INTO users (login, password, password_vault, role, full_name, account_enabled, developer_access) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [login.trim(), hashPassword(accountPassword), encryptPassword(accountPassword, passwordVaultKey), role, full_name.trim(), account_enabled ? 1 : 0, hasDeveloperAccess]);
      res.json({ success: true, generated_password: generatedPassword });
    } catch (e) {
      res.status(400).json({ success: false, message: 'Логин уже используется' });
    }
  });

  app.put('/api/admin/accounts/:id', requireRole('admin'), async (req, res) => {
    const { login, password, role, full_name, account_enabled, developer_access = 0 } = req.body;
    const roles = ['student', 'teacher', 'worker', 'supervisor'];
    if (!login || !full_name || !roles.includes(role)) {
      return res.status(400).json({ success: false, message: 'Заполните обязательные поля' });
    }
    if (password && !/^[A-Za-z0-9]{8,9}$/.test(password)) return res.status(400).json({ success: false, message: 'Пароль должен содержать 8–9 латинских букв или цифр' });
    try {
      const fields = ['login = ?', 'role = ?', 'full_name = ?', 'account_enabled = ?', 'developer_access = ?'];
      const params = [login.trim(), role, full_name.trim(), account_enabled ? 1 : 0, ['teacher', 'worker'].includes(role) && (developer_access === true || developer_access === 1) ? 1 : 0];
      if (password) {
        fields.push('password = ?', 'password_vault = ?');
        params.push(hashPassword(password), encryptPassword(password, passwordVaultKey));
      }
      params.push(req.params.id);
      await db.run(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, params);
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ success: false, message: 'Логин уже используется' });
    }
  });

  app.put('/api/admin/accounts/:id/status', requireRole('admin'), async (req, res) => {
    await db.run(`UPDATE users SET account_enabled = ? WHERE id = ?`, [req.body.account_enabled ? 1 : 0, req.params.id]);
    res.json({ success: true });
  });

  app.delete('/api/admin/accounts/:id', requireRole('admin'), async (req, res) => {
    const account = await db.one(`SELECT id FROM users WHERE id = ?`, [req.params.id]);
    if (!account) return res.status(404).json({ success: false, message: 'Пользователь не найден' });

    try {
      await transaction(async tx => {
        await tx.run(`DELETE FROM grades WHERE student_id = ?`, [account.id]);
        await tx.run(`DELETE FROM attendance WHERE student_id = ?`, [account.id]);
        await tx.run(`DELETE FROM evaluation_results WHERE student_id = ?`, [account.id]);
        await tx.run(`DELETE FROM attendance_records WHERE student_id = ?`, [account.id]);
        await tx.run(`DELETE FROM dpk_program_teachers WHERE teacher_id = ?`, [account.id]);
        await tx.run(`DELETE FROM dpk_program_evaluators WHERE teacher_id = ?`, [account.id]);
        await tx.run(`DELETE FROM dpk_teacher_lesson_dates WHERE teacher_id = ?`, [account.id]);
        await tx.run(`UPDATE dpk_lessons SET teacher_id = NULL WHERE teacher_id = ?`, [account.id]);
        await tx.run(`UPDATE schedule_entries SET teacher_id = NULL WHERE teacher_id = ?`, [account.id]);
        await tx.run(`DELETE FROM users WHERE id = ?`, [account.id]);
      });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Не удалось удалить пользователя' });
    }
  });

  app.post('/api/admin/accounts/:id/reset-password', requireRole('admin'), async (req, res) => {
    const account = await db.one(`SELECT id FROM users WHERE id = ?`, [req.params.id]);
    if (!account) return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    const generatedPassword = generatePassword();
    await db.run(`UPDATE users SET password = ?, password_vault = ? WHERE id = ?`, [hashPassword(generatedPassword), encryptPassword(generatedPassword, passwordVaultKey), req.params.id]);
    res.json({ success: true, generated_password: generatedPassword });
  });

  app.get('/api/admin/accounts/:id/password', requireRole('admin'), async (req, res) => {
    const account = await db.one(`SELECT password_vault FROM users WHERE id = ?`, [req.params.id]);
    if (!account) return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    if (!account.password_vault) return res.status(404).json({ success: false, message: 'Пароль недоступен до сброса' });
    try {
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, password: decryptPassword(account.password_vault, passwordVaultKey) });
    } catch {
      res.status(500).json({ success: false, message: 'Не удалось расшифровать пароль' });
    }
  });

  app.post('/api/admin/accounts/credentials', requireRole('admin'), async (req, res) => {
    const ids = [...new Set((Array.isArray(req.body.ids) ? req.body.ids : []).map(Number).filter(Number.isInteger))];
    if (!ids.length || ids.length > 250) return res.status(400).json({ success: false, message: 'Выберите от 1 до 250 учетных записей' });
    const rows = await db.all(`SELECT id, login, role, full_name, password_vault FROM users WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
    const byId = new Map(rows.map(row => [row.id, row]));
    const credentials = [];
    const unavailable_ids = [];
    ids.forEach(id => {
      const account = byId.get(id);
      if (!account?.password_vault) { unavailable_ids.push(id); return; }
      try {
        credentials.push({ id, login: account.login, role: account.role, full_name: account.full_name, password: decryptPassword(account.password_vault, passwordVaultKey) });
      } catch {
        unavailable_ids.push(id);
      }
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, credentials, unavailable_ids });
  });

  app.get('/api/admin/system-status', requireRole('admin'), async (req, res) => {
    const row = await db.one(`SELECT setting_value FROM system_settings WHERE setting_key = 'system_enabled'`) || { setting_value: '1' };
    res.json({ system_enabled: row.setting_value === '1' });
  });

  app.put('/api/admin/system-status', requireRole('admin'), async (req, res) => {
    await db.run(`INSERT INTO system_settings (setting_key, setting_value) VALUES ('system_enabled', ?)
      ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value`, [req.body.system_enabled ? '1' : '0']);
    res.json({ success: true, system_enabled: !!req.body.system_enabled });
  });

  app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
  });

  app.get('/api/me', (req, res) => {
    if (!req.session.user) return res.json({ user: null });
    res.json({ user: req.session.user });
  });

  app.get('/api/system-status', async (req, res) => {
    const row = await db.one(`SELECT setting_value FROM system_settings WHERE setting_key = 'system_enabled'`) || { setting_value: '1' };
    res.json({ system_enabled: row.setting_value === '1' });
  });

  async function bookingConflict(room, eventDate, timeStart, timeEnd, excludeId = null) {
    const scheduleConflict = await db.exists(`SELECT id FROM schedule_entries WHERE room = ? AND date = ? AND time_start < ? AND time_end > ? LIMIT 1`, [room, eventDate, timeEnd, timeStart]);
    if (scheduleConflict) return true;
    let sql = `SELECT * FROM booking_requests WHERE room = ? AND status = 'approved' AND time_start < ? AND time_end > ?`;
    const params = [room, timeEnd, timeStart];
    if (excludeId) { sql += ` AND id != ?`; params.push(excludeId); }
    const bookings = await db.all(sql, params);
    let bookingExists = false;
    for (const booking of bookings) {
      if (bookingOccurrenceDates(booking).includes(eventDate)) {
        bookingExists = true;
        break;
      }
    }
    return bookingExists;
  }

  function bookingTimeToMinutes(value) {
    const [hours, minutes] = String(value).split(':').map(Number);
    return hours * 60 + minutes;
  }

  function parseBookingDate(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value));
    if (!match) return null;
    const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
    return date.getFullYear() === Number(match[1]) && date.getMonth() === Number(match[2]) - 1 && date.getDate() === Number(match[3]) ? date : null;
  }

  function formatBookingDate(date) {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
  }

  function bookingOccurrenceDates(request) {
    const startDate = parseBookingDate(request.event_date);
    if (!startDate || request.recurrence === 'once') return startDate ? [request.event_date] : [];
    const endDate = parseBookingDate(request.recurrence_end);
    if (!endDate || endDate < startDate) return [];
    const dates = [];
    const date = new Date(startDate);
    while (date <= endDate && dates.length < 367) {
      dates.push(formatBookingDate(date));
      if (request.recurrence === 'daily') date.setDate(date.getDate() + 1);
      else if (request.recurrence === 'weekly') date.setDate(date.getDate() + 7);
      else if (request.recurrence === 'every2weeks') date.setDate(date.getDate() + 14);
      else if (request.recurrence === 'monthly') date.setMonth(date.getMonth() + 1);
      else break;
    }
    return dates;
  }

  app.get('/api/booking/public-data', async (req, res) => {
    const rooms = (await db.all(`SELECT DISTINCT room FROM schedule_entries WHERE room IS NOT NULL AND room != '' ORDER BY room`)).map(row => row.room);
    const bookingEvents = await db.all(`SELECT id, room, title, description, event_date, time_start, time_end, recurrence, recurrence_end, event_url, status FROM booking_requests WHERE status IN ('requested', 'approved') ORDER BY event_date, time_start`);
    const events = [];
    for (const event of bookingEvents) {
      bookingOccurrenceDates(event).forEach(event_date => events.push({ ...event, event_date, source: 'booking' }));
    }
    const scheduleEvents = await db.all(`SELECT id, room, COALESCE(program_name, 'Учебное занятие') AS title, date AS event_date, time_start, time_end FROM schedule_entries WHERE room IS NOT NULL AND room != '' AND date IS NOT NULL ORDER BY date, time_start`);
    for (const event of scheduleEvents) events.push({ ...event, source: 'schedule' });
    events.sort((a, b) => a.event_date.localeCompare(b.event_date) || a.time_start.localeCompare(b.time_start));
    res.json({ rooms, events });
  });

  app.post('/api/booking/requests', async (req, res) => {
    const { requester_name, requester_email, requester_phone, organization, room, title, description, event_date, time_start, time_end, recurrence = 'once', recurrence_end, event_url, attendees } = req.body;
    const recurrences = ['once', 'daily', 'weekly', 'every2weeks', 'monthly'];
    if (!requester_name || !room || !title || !description || !event_date || !time_start || !time_end) {
      return res.status(400).json({ success: false, message: 'Заполните обязательные поля' });
    }
    const startDate = parseBookingDate(event_date);
    const endDate = recurrence === 'once' ? startDate : parseBookingDate(recurrence_end);
    const duration = bookingTimeToMinutes(time_end) - bookingTimeToMinutes(time_start);
    const maxEnd = startDate && new Date(startDate.getFullYear() + 1, startDate.getMonth(), startDate.getDate());
    if (!recurrences.includes(recurrence) || !/^\d{2}:\d{2}$/.test(time_start) || !/^\d{2}:\d{2}$/.test(time_end) || !Number.isFinite(duration) || duration < 30 || time_start < '07:00' || time_end > '21:00') {
      return res.status(400).json({ success: false, message: 'Проверьте время бронирования: 07:00–21:00, минимум 30 минут' });
    }
    if (!startDate || !endDate || endDate < startDate || endDate > maxEnd) {
      return res.status(400).json({ success: false, message: 'Проверьте даты бронирования; период повторения не может превышать один год' });
    }
    const roomExists = await db.exists(`SELECT 1 FROM schedule_entries WHERE room = ? LIMIT 1`, [room]);
    if (!roomExists) return res.status(400).json({ success: false, message: 'Выберите аудиторию из списка' });
    await db.run(`INSERT INTO booking_requests (requester_name, requester_email, requester_phone, organization, room, title, description, event_date, time_start, time_end, recurrence, recurrence_end, event_url, attendees) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [requester_name.trim(), String(requester_email || '').trim(), requester_phone || null, organization || null, room, title.trim(), description.trim(), event_date, time_start, time_end, recurrence, recurrence === 'once' ? null : recurrence_end || null, event_url || null, Number(attendees) || 1]);
    res.json({ success: true, message: 'Заявка отправлена на согласование' });
  });

  app.get('/api/booking/requests', requireRole('worker', 'supervisor'), async (req, res) => {
    let sql = `SELECT br.*, u.full_name as reviewer_name FROM booking_requests br LEFT JOIN users u ON u.id = br.reviewed_by WHERE 1=1`;
    const params = [];
    if (req.query.status) { sql += ` AND br.status = ?`; params.push(req.query.status); }
    sql += ` ORDER BY CASE br.status WHEN 'requested' THEN 0 ELSE 1 END, br.event_date, br.time_start`;
    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.put('/api/booking/requests/:id/review', requireRole('worker', 'supervisor'), async (req, res) => {
    const { status, review_comment } = req.body;
    if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ success: false, message: 'Некорректный статус' });
    const request = await db.one(`SELECT * FROM booking_requests WHERE id = ?`, [req.params.id]);
    if (!request) return res.status(404).json({ success: false, message: 'Заявка не найдена' });
    const dates = bookingOccurrenceDates(request);
    if (status === 'approved' && (!dates.length || (await Promise.all(dates.map(date => bookingConflict(request.room, date, request.time_start, request.time_end, request.id)))).some(Boolean))) {
      return res.status(409).json({ success: false, message: 'Аудитория уже занята в это время' });
    }
    await db.run(`UPDATE booking_requests SET status = ?, review_comment = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [status, review_comment || null, req.session.user.id, req.params.id]);
    res.json({ success: true });
  });

  app.get('/api/student/lessons', requireRole('student', 'teacher', 'supervisor'), async (req, res) => {
    const rows = await db.all(`
      SELECT dl.*, u.full_name as teacher_name
      FROM dpk_lessons dl
      LEFT JOIN users u ON dl.teacher_id = u.id
      WHERE dl.flow = ? AND (dl.group_name = ? OR dl.group_name IS NULL)
    `, [req.session.user.flow, req.session.user.group_name]);
    res.json(rows);
  });

  app.get('/api/student/grades', requireRole('student', 'teacher', 'supervisor'), async (req, res) => {
    const rows = await db.all(`
      SELECT g.*, dl.title as lesson_title, dl.date as lesson_date
      FROM grades g
      JOIN dpk_lessons dl ON g.lesson_id = dl.id
      WHERE g.student_id = ?
    `, [req.session.user.id]);
    res.json(rows);
  });

  app.get('/api/student/group-info', requireRole('student', 'supervisor'), async (req, res) => {
    const rows = await db.all(`
      SELECT id, full_name, flow, group_name
      FROM users
      WHERE role = 'student' AND flow = ? AND group_name = ?
    `, [req.session.user.flow, req.session.user.group_name]);
    res.json({ flow: req.session.user.flow, group: req.session.user.group_name, students: rows });
  });

  app.get('/api/teacher/students', requireRole('teacher', 'supervisor'), async (req, res) => {
    const { flow, group, faculty } = req.query;
    let sql = `SELECT id, full_name, flow, group_name, code, course, specialty, faculty, status, qualification FROM users WHERE role = 'student'`;
    const params = [];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.teacher_id = ? AND dpt.group_name = users.group_name)`;
      params.push(req.session.user.id);
    }
    if (flow) { sql += ` AND flow = ?`; params.push(flow); }
    if (group) { sql += ` AND group_name = ?`; params.push(group); }
    if (faculty) { sql += ` AND faculty = ?`; params.push(faculty); }
    sql += ` ORDER BY group_name, full_name`;

    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.get('/api/worker/courses', requireRole('worker', 'supervisor'), async (req, res) => {
    const rows = await db.all(`SELECT DISTINCT course FROM users WHERE role = 'student' AND course IS NOT NULL ORDER BY course`);
    res.json(rows.map(r => r.course));
  });

  app.post('/api/worker/course', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Укажите название курса' });
    if (await db.exists('SELECT DISTINCT course FROM users WHERE course = ?', [name])) return res.status(400).json({ success: false, message: 'Курс уже существует' });
    res.json({ success: true });
  });

  app.put('/api/worker/course', requireRole('worker', 'supervisor'), async (req, res) => {
    const { oldName, newName } = req.body;
    if (!oldName || !newName) return res.status(400).json({ success: false, message: 'Укажите старое и новое название' });
    await transaction(async tx => {
      await tx.run(`UPDATE users SET course = ? WHERE course = ?`, [newName, oldName]);
      await tx.run(`UPDATE dpk_lessons SET course = ? WHERE course = ?`, [newName, oldName]);
    });
    res.json({ success: true });
  });

  app.delete('/api/worker/course', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Укажите название курса' });
    await transaction(async tx => {
      await tx.run(`UPDATE users SET course = NULL, flow = NULL, group_name = NULL WHERE course = ?`, [name]);
      await tx.run(`UPDATE dpk_lessons SET course = NULL, flow = NULL, group_name = NULL WHERE course = ?`, [name]);
    });
    res.json({ success: true });
  });

  app.get('/api/teacher/flows', requireRole('teacher', 'supervisor', 'worker'), async (req, res) => {
    const { course } = req.query;
    let sql = `SELECT DISTINCT flow FROM users WHERE role = 'student' AND flow IS NOT NULL`;
    const params = [];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.teacher_id = ? AND dpt.group_name = users.group_name)`;
      params.push(req.session.user.id);
    }
    if (course) { sql += ` AND course = ?`; params.push(course); }
    sql += ` ORDER BY flow`;
    const rows = await db.all(sql, params);
    res.json(rows.map(r => r.flow));
  });

  app.get('/api/teacher/groups', requireRole('teacher', 'supervisor', 'worker'), async (req, res) => {
    const { course, flow, specialty, faculty } = req.query;
    let sql = `SELECT DISTINCT group_name FROM users WHERE role = 'student' AND group_name IS NOT NULL`;
    const params = [];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.teacher_id = ? AND dpt.group_name = users.group_name)`;
      params.push(req.session.user.id);
    }
    if (course) { sql += ` AND course = ?`; params.push(course); }
    if (flow) { sql += ` AND flow = ?`; params.push(flow); }
    if (specialty) { sql += ` AND specialty = ?`; params.push(specialty); }
    if (faculty) { sql += ` AND faculty = ?`; params.push(faculty); }
    sql += ` ORDER BY group_name`;

    const rows = await db.all(sql, params);
    res.json(rows.map(r => r.group_name));
  });

  app.get('/api/teacher/faculties', requireRole('teacher', 'supervisor', 'worker'), async (req, res) => {
    let sql = `SELECT DISTINCT faculty FROM users WHERE role = 'student' AND faculty IS NOT NULL AND faculty != ''`;
    const params = [];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.teacher_id = ? AND dpt.group_name = users.group_name)`;
      params.push(req.session.user.id);
    }
    sql += ` ORDER BY faculty`;
    const rows = await db.all(sql, params);
    res.json(rows.map(row => row.faculty));
  });

  app.get('/api/teacher/courses', requireRole('teacher', 'supervisor', 'worker'), async (req, res) => {
    let sql = `SELECT DISTINCT course FROM users WHERE role = 'student' AND course IS NOT NULL AND course != ''`;
    const params = [];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.teacher_id = ? AND dpt.group_name = users.group_name)`;
      params.push(req.session.user.id);
    }
    sql += ` ORDER BY course`;
    const rows = await db.all(sql, params);
    res.json(rows.map(r => r.course));
  });

  app.get('/api/teacher/specialties', requireRole('teacher', 'supervisor', 'worker'), async (req, res) => {
    const { course } = req.query;
    let sql = `SELECT DISTINCT specialty FROM users WHERE role = 'student' AND specialty IS NOT NULL AND specialty != ''`;
    const params = [];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.teacher_id = ? AND dpt.group_name = users.group_name)`;
      params.push(req.session.user.id);
    }
    if (course) { sql += ` AND course = ?`; params.push(course); }
    sql += ` ORDER BY specialty`;
    const rows = await db.all(sql, params);
    res.json(rows.map(r => r.specialty));
  });

  app.get('/api/teacher/lessons', requireRole('teacher', 'supervisor'), async (req, res) => {
    let sql = `
      SELECT se.*, u.full_name as teacher_name,
        COALESCE(se.program_name, dp.name) as program_name,
        dp.name as dpk_program_name
      FROM schedule_entries se
      LEFT JOIN users u ON se.teacher_id = u.id
      LEFT JOIN dpk_programs dp ON se.program_id = dp.id
    `;
    const params = [];
    if (req.session.user.role !== 'supervisor') {
      sql += ` WHERE se.teacher_id = ?`;
      params.push(req.session.user.id);
    }
    sql += ` ORDER BY se.date, se.time_start`;
    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.post('/api/teacher/grade', requireRole('teacher', 'supervisor'), async (req, res) => {
    const { student_id, lesson_id, grade, comment } = req.body;
    const date = new Date().toISOString().split('T')[0];
    await db.run(`INSERT INTO grades (student_id, lesson_id, grade, comment, date) VALUES (?, ?, ?, ?, ?)`,
      [student_id, lesson_id, grade, comment, date]);
    res.json({ success: true });
  });

  app.get('/api/teacher/programs', requireRole('teacher'), async (req, res) => {
    const teacher_id = req.session.user.id;
    const rows = await db.all(`
      SELECT dp.* FROM dpk_programs dp
      JOIN dpk_program_teachers dpt ON dpt.program_id = dp.id
      WHERE dpt.teacher_id = ?
      ORDER BY dp.name
    `, [teacher_id]);
    res.json(rows);
  });

  app.get('/api/teacher/dpk-programs', requireRole('teacher'), async (req, res) => {
    const teacher_id = req.session.user.id;
    const rows = await db.all(`
      SELECT dp.id, dp.name, dp.total_hours,
        SUM(COALESCE(dpt.hours, 0)) as teacher_hours,
        SUM(COALESCE(dpt.lecture_hours, 0)) as lecture_hours,
        SUM(COALESCE(dpt.practice_hours, 0)) as practice_hours,
        SUM(COALESCE(dpt.lab_hours, 0)) as lab_hours,
        COUNT(DISTINCT NULLIF(dpt.group_name, '')) as groups_count,
        STRING_AGG(DISTINCT NULLIF(dpt.group_name, ''), ',') as groups
      FROM dpk_programs dp
      JOIN dpk_program_teachers dpt ON dpt.program_id = dp.id AND dpt.teacher_id = ?
      GROUP BY dp.id, dp.name, dp.total_hours
      ORDER BY dp.name
    `, [teacher_id]);
    res.json(rows);
  });

  app.get('/api/student/dpk-programs', requireRole('student'), async (req, res) => {
    const group_name = req.session.user.group_name;
    const rows = await db.all(`
      SELECT dp.id, dp.name, SUM(COALESCE(dpt.hours, 0)) AS group_hours
      FROM dpk_programs dp
      JOIN dpk_program_groups pg ON pg.program_id = dp.id AND pg.group_name = ?
      LEFT JOIN dpk_program_teachers dpt ON dpt.program_id = dp.id AND dpt.group_name = pg.group_name
      GROUP BY dp.id, dp.name
      ORDER BY dp.name
    `, [group_name]);
    res.json(rows);
  });

  app.post('/api/teacher/schedule', requireRole('teacher', 'supervisor'), async (req, res) => {
    const { program_name, group_name, room, day_of_week, time_start, time_end, date, lesson_type } = req.body;
    const teacher_id = req.session.user.id;
    if (day_of_week === undefined || !time_start || !time_end) {
      return res.status(400).json({ success: false, message: 'Заполните обязательные поля' });
    }
    const entryDate = date || null;
    const scheduleDay = entryDate ? dayOfWeekFromDateOnly(entryDate) : Number(day_of_week);
    if (scheduleDay === null) return res.status(400).json({ success: false, message: 'Некорректная дата' });
    await db.run(`INSERT INTO schedule_entries (program_name, teacher_id, group_name, room, day_of_week, time_start, time_end, date, lesson_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [program_name || null, teacher_id, group_name || null, room || null, scheduleDay, time_start, time_end, entryDate, lesson_type || null]);
    res.json({ success: true });
  });

  app.put('/api/teacher/schedule/:id', requireRole('teacher', 'supervisor'), async (req, res) => {
    const { program_name, group_name, room, day_of_week, time_start, time_end, date, lesson_type } = req.body;
    const entry = await db.one(`SELECT id FROM schedule_entries WHERE id = ? AND teacher_id = ?`, [req.params.id, req.session.user.id]);
    if (!entry) return res.status(404).json({ success: false, message: 'Занятие не найдено' });
    const entryDate = date || null;
    const scheduleDay = entryDate ? dayOfWeekFromDateOnly(entryDate) : Number(day_of_week);
    if (scheduleDay === null) return res.status(400).json({ success: false, message: 'Некорректная дата' });
    await db.run(`UPDATE schedule_entries SET program_name = ?, group_name = ?, room = ?, day_of_week = ?, time_start = ?, time_end = ?, date = ?, lesson_type = ? WHERE id = ?`,
      [program_name || null, group_name || null, room || null, scheduleDay, time_start, time_end, entryDate, lesson_type || null, req.params.id]);
    res.json({ success: true });
  });

  app.delete('/api/teacher/schedule/:id', requireRole('teacher', 'supervisor'), async (req, res) => {
    const entry = await db.one(`SELECT program_id, teacher_id FROM schedule_entries WHERE id = ? AND teacher_id = ?`, [req.params.id, req.session.user.id]);
    if (!entry) return res.status(404).json({ success: false, message: 'Занятие не найдено' });
    await db.run(`DELETE FROM schedule_entries WHERE id = ?`, [req.params.id]);
    if (entry.program_id) await recalcProgramTeacherHours(entry.program_id, entry.teacher_id);
    res.json({ success: true });
  });

  app.post('/api/teacher/schedule/import-ics', upload.single('file'), requireRole('teacher'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ success: false, message: 'Файл не загружен' });
      const icsData = req.file.buffer.toString('utf8');
      const teacher_id = req.session.user.id;
      const program_name = req.body.program_name ? req.body.program_name.trim() : null;

      // Basic ICS VEVENT parser
      const events = [];
      const veventRegex = /BEGIN:VEVENT([\s\S]*?)END:VEVENT/g;
      let match;
      while ((match = veventRegex.exec(icsData)) !== null) {
        const block = match[1];
        const getVal = (key) => {
          const r = new RegExp(key + '(?:;[^:]*)?:(.+)', 'm');
          const m = block.match(r);
          return m ? m[1].trim() : '';
        };
        const dtstart = getVal('DTSTART');
        const dtend = getVal('DTEND');
        const summary = getVal('SUMMARY');
        const location = getVal('LOCATION');
        if (!dtstart || dtstart.length < 8) continue;

        // Parse date and time from ICS format: YYYYMMDD or YYYYMMDDTHHMMSS
        let dateStr, startTime, endTime;
        if (dtstart.includes('T')) {
          const parts = dtstart.split('T');
          dateStr = parts[0].slice(0, 4) + '-' + parts[0].slice(4, 6) + '-' + parts[0].slice(6, 8);
          const s = parts[1].replace('Z', '');
          startTime = s.slice(0, 2) + ':' + s.slice(2, 4);
        } else {
          dateStr = dtstart.slice(0, 4) + '-' + dtstart.slice(4, 6) + '-' + dtstart.slice(6, 8);
          startTime = '00:00';
        }
        if (dtend && dtend.includes('T')) {
          const parts = dtend.split('T');
          const s = parts[1].replace('Z', '');
          endTime = s.slice(0, 2) + ':' + s.slice(2, 4);
        } else {
          endTime = '23:59';
        }

        // Compute day_of_week (0=Mon)
        const d = new Date(dateStr + 'T12:00:00');
        if (isNaN(d.getTime())) continue;
        const day_of_week = d.getDay() === 0 ? 6 : d.getDay() - 1;

        events.push({
          program_name,
          teacher_id,
          group_name: summary || null,
          room: location || null,
          day_of_week,
          time_start: startTime,
          time_end: endTime,
          date: dateStr
        });
      }

      if (!events.length) {
        return res.status(400).json({ success: false, message: 'Не найдено событий в ICS файле' });
      }

      let imported = 0;
      for (const e of events) {
        if (e.day_of_week < 0 || e.day_of_week > 6) continue;
        await db.run(`INSERT INTO schedule_entries (program_name, teacher_id, group_name, room, day_of_week, time_start, time_end, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [e.program_name, e.teacher_id, e.group_name, e.room, e.day_of_week, e.time_start, e.time_end, e.date]);
        imported++;
      }
      res.json({ success: true, imported });
    } catch (err) {
      console.error('ICS import error:', err);
      res.status(500).json({ success: false, message: 'Ошибка импорта ICS: ' + err.message });
    }
  });

  app.get('/api/worker/teachers', requireRole('worker', 'supervisor'), async (req, res) => {
    const rows = await db.all(`SELECT id, full_name, login, code, title, work_type, position, department, supervisor_name, category FROM users WHERE role = 'teacher' ORDER BY full_name`);
    res.json(rows);
  });

  app.post('/api/worker/teacher', requireRole('worker', 'supervisor'), async (req, res) => {
    let { full_name, code, title, work_type, position, department, supervisor_name, category } = req.body;
    if (!full_name) return res.status(400).json({ success: false, message: 'ФИО обязательно' });
    const login = await uniqueStaffLogin(db, full_name);
    const autoCategory = category || String(calculateCategory(position, title));
    const generatedPassword = generatePassword();
    await db.run(`INSERT INTO users (login, password, password_vault, role, full_name, code, title, work_type, position, department, supervisor_name, category) VALUES (?, ?, ?, 'teacher', ?, ?, ?, ?, ?, ?, ?, ?)`,
      [login, hashPassword(generatedPassword), encryptPassword(generatedPassword, passwordVaultKey), full_name, code || null, title || null, work_type || null, position || null, department || null, supervisor_name || null, autoCategory]);
    res.json({ success: true });
  });

  function calculateCategory(position, degree) {
    const d = (degree || '').trim().toLowerCase().replace(/\./g, '');
    const p = (position || '').trim().toLowerCase();
    if (d.includes('дтн') || d.includes('дэн') || d.includes('доктор')) return 1;
    if (d.includes('ктн') || d.includes('кэн') || d.includes('кандидат')) return 2;
    if (p.includes('ассистент') && !d) return 3;
    if (p.includes('аспирант')) return 4;
    return 4;
  }

  async function recalcProgramTeacherHours(program_id, teacher_id) {
    const cnt = await db.one(`SELECT COUNT(*) AS c FROM schedule_entries WHERE program_id = ? AND teacher_id = ?`, [program_id, teacher_id]) || { c: 0 };
    const hours = (cnt.c || 0) * 2;
    const ex = await db.one(`SELECT id FROM dpk_program_teachers WHERE program_id = ? AND teacher_id = ? LIMIT 1`, [program_id, teacher_id]);
    if (ex) {
      await db.run(`UPDATE dpk_program_teachers SET hours = ? WHERE id = ?`, [hours, ex.id]);
    } else {
      await db.run(`INSERT INTO dpk_program_teachers (program_id, teacher_id, group_name, hours) VALUES (?, ?, '', ?) ON CONFLICT (program_id, group_name, teacher_id) DO UPDATE SET hours = EXCLUDED.hours`, [program_id, teacher_id, hours]);
    }
    await recalcProgramTotalHours(program_id);
  }

  async function recalcProgramTotalHours(program_id) {
    const row = await db.one(`SELECT COALESCE(SUM(hours), 0) AS total FROM dpk_program_teachers WHERE program_id = ?`, [program_id]) || { total: 0 };
    await db.run(`UPDATE dpk_programs SET total_hours = ? WHERE id = ?`, [row.total, program_id]);
  }

  app.put('/api/worker/teacher/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const { full_name, code, title, work_type, position, department, supervisor_name, category } = req.body;
    if (!full_name) return res.status(400).json({ success: false, message: 'ФИО обязательно' });
    const login = await uniqueStaffLogin(db, full_name, Number(req.params.id));
    const autoCategory = category || String(calculateCategory(position, title));
    let sql = `UPDATE users SET login = ?, full_name = ?, code = ?, title = ?, work_type = ?, position = ?, department = ?, supervisor_name = ?, category = ?`;
    const params = [login, full_name, code || null, title || null, work_type || null, position || null, department || null, supervisor_name || null, autoCategory];
    sql += ` WHERE id = ? AND role = 'teacher'`;
    params.push(req.params.id);
    await db.run(sql, params);
    res.json({ success: true });
  });

  app.delete('/api/worker/teacher/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    await db.run(`DELETE FROM users WHERE id = ? AND role = 'teacher'`, [req.params.id]);
    res.json({ success: true });
  });

  app.get('/api/worker/students', requireRole('worker', 'supervisor'), async (req, res) => {
    const { course, specialty, flow, group, search } = req.query;
    let sql = `SELECT id, full_name, login, course, specialty, flow, group_name, code, subgroup, status, faculty, qualification, department FROM users WHERE role = 'student'`;
    const params = [];
    if (course) { sql += ` AND course = ?`; params.push(course); }
    if (specialty) { sql += ` AND specialty = ?`; params.push(specialty); }
    if (flow) { sql += ` AND flow = ?`; params.push(flow); }
    if (group) { sql += ` AND group_name = ?`; params.push(group); }
    if (search) { sql += ` AND (full_name LIKE ? OR login LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`); }
    sql += ` ORDER BY full_name`;

    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.get('/api/worker/students/export', requireRole('worker', 'supervisor'), async (req, res) => {
    const { course, specialty, flow, group, search } = req.query;
    let sql = `SELECT login, full_name, course, specialty, flow, group_name, code, subgroup, status, faculty, qualification, department FROM users WHERE role = 'student'`;
    const params = [];
    if (course) { sql += ` AND course = ?`; params.push(course); }
    if (specialty) { sql += ` AND specialty = ?`; params.push(specialty); }
    if (flow) { sql += ` AND flow = ?`; params.push(flow); }
    if (group) { sql += ` AND group_name = ?`; params.push(group); }
    if (search) { sql += ` AND (full_name LIKE ? OR login LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`); }
    sql += ` ORDER BY full_name`;

    const rows = await db.all(sql, params);

    const ws = XLSX.utils.json_to_sheet(rows.map(r => ({
      'Логин': r.login,
      'ФИО': r.full_name,
      'Факультет': r.faculty || '',
      'Кафедра': r.department || '',
      'Курс': r.course || '',
      'Специальность': r.specialty || '',
      'Группа': r.group_name || '',
      'Квалификация': r.qualification || '',
      'Шифр': r.code || '',
      'Подгруппа': r.subgroup || '',
      'Статус': r.status || 'Активен'
    })));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Students');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent('Список студентов.xlsx'));
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  });

  app.get('/api/worker/teachers/export', requireRole('worker', 'supervisor'), async (req, res) => {
    const rows = await db.all(`SELECT login, full_name, code, title, work_type, position, department, supervisor_name, category FROM users WHERE role = 'teacher' ORDER BY full_name`);

    const ws = XLSX.utils.json_to_sheet(rows.map(r => ({
      'Логин': r.login,
      'ФИО': r.full_name,
      'Шифр': r.code || '',
      'Название': r.title || '',
      'Вид работы': r.work_type || '',
      'Должность': r.position || '',
      'Структурное подразделение': r.department || '',
      'Руководитель': r.supervisor_name || '',
      'Категория': r.category || ''
    })));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Teachers');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent('Список преподавателей.xlsx'));
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  });

  app.post('/api/worker/teachers/import', upload.single('file'), requireRole('worker', 'supervisor'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ success: false, message: 'Файл не загружен' });

      const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const data = XLSX.utils.sheet_to_json(sheet);
      let imported = 0;
      let updated = 0;
      let skipped = 0;
      let teachers = 0;
      let workers = 0;

      for (const row of data) {
        const fullName = String(row.full_name || row.ФИО || '').trim();
        if (!fullName) { skipped++; continue; }

        const importedPassword = String(row.password || row.Пароль || '').trim();
        const code = String(row.code || row.Шифр || '').trim();
        const title = String(row.title || row.Название || row.Звание || '').trim();
        const workType = String(row.work_type || row['Вид работы'] || '').trim();
        const position = String(row.position || row.Должность || '').trim();
        const department = String(row.department || row['Структурное подразделение'] || row.Подразделение || row.Кафедра || '').trim();
        const supervisorName = String(row.supervisor_name || row.Руководитель || '').trim();
        const suppliedCategory = String(row.category || row.Категория || '').trim();
        const targetRole = classifyStaffRole(title, position);
        if (targetRole === 'teacher') teachers++; else workers++;

        let login = String(row.login || row.Логин || '').trim();
        let existingStaff = null;
        if (login) {
          const account = await db.one('SELECT id, login, role FROM users WHERE login = ?', [login]);
          if (account && !['teacher', 'worker'].includes(account.role)) { skipped++; continue; }
          if (account) existingStaff = account;
        }

        if (!existingStaff) {
          existingStaff = await db.one(`SELECT id, login, role FROM users WHERE role IN ('teacher', 'worker') AND TRIM(full_name) = ? ORDER BY CASE WHEN role = ? THEN 0 ELSE 1 END LIMIT 1`, [fullName, targetRole]);
        }

        login = await uniqueStaffLogin(db, fullName, existingStaff?.id);

        const password = importedPassword && isValidPassword(importedPassword) ? importedPassword : generatePassword();
        const category = suppliedCategory || String(calculateCategory(position, title));

        if (existingStaff) {
          const fields = ['login = ?', 'role = ?', 'full_name = ?', 'code = ?', 'title = ?', 'work_type = ?', 'position = ?', 'department = ?', 'supervisor_name = ?', 'category = ?'];
          const params = [login, targetRole, fullName, code || null, title || null, workType || null, position || null, department || null, supervisorName || null, category];
          if (importedPassword && isValidPassword(importedPassword)) {
            fields.push('password = ?', 'password_vault = ?');
            params.push(hashPassword(importedPassword), encryptPassword(importedPassword, passwordVaultKey));
          } else if (targetRole === 'teacher' && existingStaff.role !== 'teacher') {
            const generatedPassword = generatePassword();
            fields.push('password = ?', 'password_vault = ?');
            params.push(hashPassword(generatedPassword), encryptPassword(generatedPassword, passwordVaultKey));
          }
          params.push(existingStaff.id);
          await db.run(`UPDATE users SET ${fields.join(', ')} WHERE id = ? AND role IN ('teacher', 'worker')`, params);
          updated++;
        } else {
          await db.run(`INSERT INTO users (login, password, password_vault, role, full_name, code, title, work_type, position, department, supervisor_name, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [login, hashPassword(password), encryptPassword(password, passwordVaultKey), targetRole, fullName, code || null, title || null, workType || null, position || null, department || null, supervisorName || null, category]);
          imported++;
        }
      }

      res.json({ success: true, imported, updated, skipped, teachers, workers, total: data.length });
    } catch (err) {
      res.status(400).json({ success: false, message: 'Ошибка при обработке файла: ' + err.message });
    }
  });

  app.post('/api/worker/import', upload.single('file'), requireRole('worker', 'supervisor'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ success: false, message: 'Файл не загружен' });

      const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const data = studentRowsFromSheet(sheet);

      let imported = 0;
      let updated = 0;
      let skipped = 0;
      for (const row of data) {
        const suppliedLogin = String(excelValue(row, ['login', 'Логин', 'Имя пользователя'])).trim();
        const importedPassword = String(excelValue(row, ['password', 'Пароль'])).trim();
        const password = importedPassword && isValidPassword(importedPassword) ? importedPassword : generatePassword();
        const fullName = String(excelValue(row, ['full_name', 'ФИО', 'Ф.И.О.', 'ФИО студента', 'Студент', 'Полное имя'])).trim();
        const course = String(excelValue(row, ['course', 'Курс'])).trim();
        const specialty = String(excelValue(row, ['specialty', 'Специальность', 'Направление', 'Направление подготовки'])).trim();
        const flow = String(excelValue(row, ['flow', 'Поток'])).trim();
        const group = String(excelValue(row, ['group_name', 'Группа', 'Учебная группа', 'Имя группы'])).trim();
        const code = String(excelValue(row, ['code', 'Шифр', 'Код', 'Номер зачетной книжки'])).trim();
        const subgroup = String(excelValue(row, ['subgroup', 'Подгруппа'])).trim();
        const status = String(excelValue(row, ['status', 'Статус'])).trim() || 'Активен';
        const faculty = String(excelValue(row, ['faculty', 'Факультет'])).trim();
        const qualification = String(excelValue(row, ['qualification', 'Квалификация', 'Квалицикация'])).trim();
        const department = String(excelValue(row, ['department', 'Кафедра', 'Подразделение'])).trim();

        if (!fullName) { skipped++; continue; }

        let existingStudent = null;
        if (suppliedLogin) {
          existingStudent = await db.one('SELECT id, role FROM users WHERE LOWER(login) = LOWER(?)', [suppliedLogin]);
          if (existingStudent && existingStudent.role !== 'student') { skipped++; continue; }
        }
        if (!existingStudent && code) {
          existingStudent = await db.one(`SELECT id, role FROM users WHERE role = 'student' AND code = ?`, [code]);
        }
        if (!existingStudent && !suppliedLogin) {
          existingStudent = await db.one(`SELECT id, role FROM users WHERE role = 'student' AND LOWER(full_name) = LOWER(?) AND COALESCE(group_name, '') = ?`, [fullName, group]);
        }

        if (existingStudent) {
          await db.run(`UPDATE users SET full_name = ?, course = ?, specialty = ?, flow = ?, group_name = ?, code = ?, subgroup = ?, status = ?, faculty = ?, qualification = ?, department = ? WHERE id = ? AND role = 'student'`,
            [fullName, course || null, specialty || null, flow || null, group || null, code || null, subgroup || null, status, faculty || null, qualification || null, department || null, existingStudent.id]);
          updated++;
        } else {
          const login = suppliedLogin || await uniqueStudentLogin(db, fullName, code);
          await db.run(`INSERT INTO users (login, password, password_vault, role, full_name, course, specialty, flow, group_name, code, subgroup, status, faculty, qualification, department) VALUES (?, ?, ?, 'student', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [login, hashPassword(password), encryptPassword(password, passwordVaultKey), fullName, course || null, specialty || null, flow || null, group || null, code || null, subgroup || null, status, faculty || null, qualification || null, department || null]);
          imported++;
        }
      }

      res.json({ success: true, imported, updated, skipped, total: data.length });
    } catch (err) {
      res.status(400).json({ success: false, message: 'Ошибка при обработке файла: ' + err.message });
    }
  });

  app.post('/api/worker/student', requireRole('worker', 'supervisor'), async (req, res) => {
    const { login, password, full_name, course, specialty, group_name, code, status, faculty, qualification, department } = req.body;
    if (!login || !full_name) return res.status(400).json({ success: false, message: 'Логин и ФИО обязательны' });
    if (password && !isValidPassword(password)) return res.status(400).json({ success: false, message: 'Пароль должен содержать 8–10 латинских букв или цифр' });
    if (await db.exists('SELECT id FROM users WHERE login = ?', [login])) return res.status(400).json({ success: false, message: 'Логин уже существует' });
    const accountPassword = password || generatePassword();
    await db.run(`INSERT INTO users (login, password, password_vault, role, full_name, course, specialty, group_name, code, status, faculty, qualification, department) VALUES (?, ?, ?, 'student', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [login, hashPassword(accountPassword), encryptPassword(accountPassword, passwordVaultKey), full_name, course || null, specialty || null, group_name || null, code || null, status || 'Активен', faculty || null, qualification || null, department || null]);
    res.json({ success: true });
  });

  app.put('/api/worker/student/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const { full_name, course, specialty, group_name, code, status, faculty, qualification, department } = req.body;
    await db.run(`UPDATE users SET full_name = ?, course = ?, specialty = ?, group_name = ?, code = ?, status = ?, faculty = ?, qualification = ?, department = ? WHERE id = ? AND role = 'student'`,
      [full_name, course || null, specialty || null, group_name || null, code || null, status || 'Активен', faculty || null, qualification || null, department || null, req.params.id]);
    res.json({ success: true });
  });

  app.delete('/api/worker/student/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    await db.run(`DELETE FROM users WHERE id = ? AND role = 'student'`, [req.params.id]);
    res.json({ success: true });
  });

  app.get('/api/worker/specialties', requireRole('worker', 'supervisor'), async (req, res) => {
    const { course } = req.query;
    let sql = `SELECT DISTINCT specialty FROM users WHERE role = 'student' AND specialty IS NOT NULL`;
    const params = [];
    if (course) { sql += ` AND course = ?`; params.push(course); }
    sql += ` ORDER BY specialty`;
    const rows = await db.all(sql, params);
    res.json(rows.map(r => r.specialty));
  });

  app.post('/api/worker/flow', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Укажите название потока' });
    if (await db.exists('SELECT DISTINCT flow FROM users WHERE flow = ?', [name])) return res.status(400).json({ success: false, message: 'Поток уже существует' });
    res.json({ success: true });
  });

  app.put('/api/worker/flow', requireRole('worker', 'supervisor'), async (req, res) => {
    const { oldName, newName } = req.body;
    if (!oldName || !newName) return res.status(400).json({ success: false, message: 'Укажите старое и новое название' });
    await db.run(`UPDATE users SET flow = ? WHERE flow = ?`, [newName, oldName]);
    res.json({ success: true });
  });

  app.delete('/api/worker/flow', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Укажите название потока' });
    await db.run(`UPDATE users SET flow = NULL, group_name = NULL WHERE flow = ?`, [name]);
    res.json({ success: true });
  });

  app.get('/api/worker/groups/all', requireRole('worker', 'supervisor'), async (req, res) => {
    const rows = await db.all(`SELECT DISTINCT group_name FROM users WHERE role = 'student' AND group_name IS NOT NULL ORDER BY group_name`);
    res.json(rows.map(r => r.group_name));
  });

  app.post('/api/worker/group', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Укажите название группы' });
    if (await db.exists('SELECT DISTINCT group_name FROM users WHERE group_name = ?', [name])) return res.status(400).json({ success: false, message: 'Группа уже существует' });
    res.json({ success: true });
  });

  app.put('/api/worker/group', requireRole('worker', 'supervisor'), async (req, res) => {
    const { oldName, newName, flow } = req.body;
    if (!oldName || !newName) return res.status(400).json({ success: false, message: 'Укажите старое и новое название' });
    let sql = `UPDATE users SET group_name = ? WHERE group_name = ?`;
    const params = [newName, oldName];
    if (flow) { sql += ` AND flow = ?`; params.push(flow); }
    await db.run(sql, params);
    res.json({ success: true });
  });

  app.delete('/api/worker/group', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name, flow } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Укажите название группы' });
    let sql = `UPDATE users SET group_name = NULL WHERE group_name = ?`;
    const params = [name];
    if (flow) { sql += ` AND flow = ?`; params.push(flow); }
    await db.run(sql, params);
    res.json({ success: true });
  });

  app.get('/api/supervisor/teachers', requireRole('supervisor'), async (req, res) => {
    const rows = await db.all(`SELECT id, full_name, login, code, title, work_type, position, department, supervisor_name, category FROM users WHERE role = 'teacher' ORDER BY full_name`);
    res.json(rows);
  });

  app.get('/api/supervisor/stats', requireRole('supervisor'), async (req, res) => {
    const [studentRow, teacherRow, lessonRow, absentRow] = await Promise.all([
      db.one(`SELECT COUNT(*) as c FROM users WHERE role = 'student'`),
      db.one(`SELECT COUNT(*) as c FROM users WHERE role = 'teacher'`),
      db.one(`SELECT COUNT(*) as c FROM dpk_lessons`),
      db.one(`SELECT COUNT(*) as c FROM attendance WHERE date = CURRENT_DATE AND status = 'absent'`)
    ]);
    const students = studentRow.c, teachers = teacherRow.c, lessons = lessonRow.c, absentToday = absentRow.c;

    res.json({ students, teachers, lessons, absentToday });
  });

  app.get('/api/supervisor/students-full', requireRole('supervisor'), async (req, res) => {
    const { flow, group } = req.query;
    let sql = `SELECT id, full_name, login, flow, group_name FROM users WHERE role = 'student'`;
    const params = [];
    if (flow) { sql += ` AND flow = ?`; params.push(flow); }
    if (group) { sql += ` AND group_name = ?`; params.push(group); }
    sql += ` ORDER BY full_name`;

    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.get('/api/supervisor/evaluation', requireRole('supervisor'), async (req, res) => {
    const { course, flow, group } = req.query;
    const lessonIds = {};
    const lessons = await db.all(`SELECT id, group_name FROM dpk_lessons WHERE title = '3Д моделирование и визуализация'`);
    for (const l of lessons) {
      lessonIds[l.group_name] = l.id;
    }

    let sql = `SELECT u.id, u.full_name, u.flow, u.group_name, u.course, g.grade, g.comment, g.id as grade_id
      FROM users u
      LEFT JOIN grades g ON g.student_id = u.id AND g.lesson_id IN (SELECT id FROM dpk_lessons WHERE title = '3Д моделирование и визуализация')
      WHERE u.role = 'student'`;
    const params = [];
    if (course) { sql += ` AND u.course = ?`; params.push(course); }
    if (flow) { sql += ` AND u.flow = ?`; params.push(flow); }
    if (group) { sql += ` AND u.group_name = ?`; params.push(group); }
    sql += ` ORDER BY u.full_name`;

    const rows = await db.all(sql, params);
    for (const r of rows) {
      r.lesson_id = lessonIds[r.group_name] || null;
    }
    res.json({ students: rows, lessonIds });
  });

  app.get('/api/evaluation/programs', requireRole('supervisor', 'teacher'), async (req, res) => {
    let sql = `SELECT dp.*,
      (SELECT COUNT(DISTINCT er.student_id) FROM evaluation_results er WHERE er.program_id = dp.id) as evaluated_count,
      (SELECT COUNT(DISTINCT u.id) FROM users u JOIN dpk_program_groups pg ON pg.program_id = dp.id AND pg.group_name = u.group_name WHERE u.role = 'student') as students_count,
      (SELECT COUNT(DISTINCT pg.group_name) FROM dpk_program_groups pg WHERE pg.program_id = dp.id) as groups_count
      FROM dpk_programs dp`;
    const params = [];
    if (req.session.user.role === 'teacher') {
      sql += ` JOIN dpk_program_evaluators dpe ON dpe.program_id = dp.id AND dpe.teacher_id = ?`;
      params.push(req.session.user.id);
    }
    sql += ` ORDER BY dp.name`;
    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.get('/api/attendance/teacher-programs', requireRole('teacher'), async (req, res) => {
    const rows = await db.all(`
      SELECT DISTINCT dp.*,
        (SELECT COUNT(*) FROM evaluation_results er WHERE er.program_id = dp.id) as evaluated_count,
        (SELECT COUNT(DISTINCT assigned.group_name) FROM dpk_program_teachers assigned WHERE assigned.program_id = dp.id AND assigned.teacher_id = ? AND assigned.group_name != '') as groups_count
      FROM dpk_programs dp
      JOIN dpk_program_teachers dpt ON dpt.program_id = dp.id AND dpt.teacher_id = ? AND dpt.group_name != ''
      ORDER BY dp.name
    `, [req.session.user.id, req.session.user.id]);
    res.json(rows);
  });

  app.get('/api/evaluation/program/:id', requireRole('supervisor', 'teacher'), async (req, res) => {
    const programId = req.params.id;
    if (req.session.user.role === 'teacher' && !await teacherIsEvaluator(req.session.user.id, programId)) {
      return res.status(403).json({ success: false, message: 'Нет доступа к оцениванию этой программы' });
    }
    const { course, specialty, group_name, search } = req.query;
    let sql = `
      SELECT u.id, u.full_name, u.course, u.specialty, u.group_name, u.subgroup,
        er.id as result_id, er.subgroup as eval_subgroup,
        (SELECT COUNT(*) FROM attendance_records ar WHERE ar.student_id = u.id AND ar.program_id = ? AND ar.class_type = 'lecture' AND ar.status = 'absent') as missed_lectures,
        (SELECT COUNT(*) FROM attendance_records ar WHERE ar.student_id = u.id AND ar.program_id = ? AND ar.class_type = 'practice' AND ar.status = 'absent') as missed_practicals,
        er.admission,
        er.model_detail_level, er.model_originality, er.model_files_on_disk,
        er.bonus_render, er.bonus_animation, er.bonus_interesting_model,
        er.has_guides, er.dashboard_blocks, er.chart_errors,
        er.bonus_design, er.bonus_program_implementation,
        er.defense_score, er.total_score, er.grade, er.fact
      FROM users u
      JOIN dpk_program_groups pg ON pg.program_id = ? AND pg.group_name = u.group_name
      LEFT JOIN evaluation_results er ON er.student_id = u.id AND er.program_id = ?
      WHERE u.role = 'student'`;
    const params = [programId, programId, programId, programId];
    if (course) { sql += ` AND u.course = ?`; params.push(course); }
    if (specialty) { sql += ` AND u.specialty = ?`; params.push(specialty); }
    if (group_name) { sql += ` AND u.group_name = ?`; params.push(group_name); }
    if (search) { sql += ` AND u.full_name LIKE ?`; params.push(`%${search}%`); }
    sql += ` ORDER BY u.group_name, u.full_name`;
    const rows = await db.all(sql, params);
    // Auto-calculate admission
    rows.forEach(r => {
      const ml = r.missed_lectures || 0;
      if (ml >= 2) r.admission = 'НЕДОПУСК';
      else if (ml >= 1) r.admission = 'ДОП. ВОПРОС';
      else r.admission = 'ДОПУСК';
    });
    res.json(rows);
  });

  app.get('/api/evaluation/program/:id/filters', requireRole('supervisor', 'teacher'), async (req, res) => {
    if (req.session.user.role === 'teacher' && !await teacherIsEvaluator(req.session.user.id, req.params.id)) {
      return res.status(403).json({ success: false, message: 'Нет доступа к оцениванию этой программы' });
    }
    const { course, specialty } = req.query;
    let sql = `SELECT DISTINCT u.course, u.specialty, u.group_name
      FROM users u
      JOIN dpk_program_groups pg ON pg.program_id = ? AND pg.group_name = u.group_name
      WHERE u.role = 'student'`;
    const params = [req.params.id];
    if (course) { sql += ` AND u.course = ?`; params.push(course); }
    if (specialty) { sql += ` AND u.specialty = ?`; params.push(specialty); }
    sql += ` ORDER BY u.course, u.specialty, u.group_name`;
    const rows = await db.all(sql, params);
    const courses = new Set(), specialties = new Set(), groups = new Set();
    for (const row of rows) {
      if (row.course) courses.add(row.course);
      if (row.specialty) specialties.add(row.specialty);
      if (row.group_name) groups.add(row.group_name);
    }
    res.json({ courses: [...courses], specialties: [...specialties], groups: [...groups] });
  });

  app.post('/api/evaluation/program/:id', requireRole('supervisor', 'teacher'), async (req, res) => {
    const programId = req.params.id;
    if (req.session.user.role === 'teacher' && !await teacherIsEvaluator(req.session.user.id, programId)) {
      return res.status(403).json({ success: false, message: 'Нет доступа к оцениванию этой программы' });
    }
    const b = req.body;
    const studentInProgram = await db.exists(`SELECT 1 FROM users u JOIN dpk_program_groups pg ON pg.program_id = ? AND pg.group_name = u.group_name WHERE u.id = ? AND u.role = 'student'`, [programId, b.student_id]);
    if (!studentInProgram) return res.status(400).json({ success: false, message: 'Студент не относится к этой программе' });
    const existingRow = await db.one('SELECT * FROM evaluation_results WHERE program_id = ? AND student_id = ?', [programId, b.student_id]);
    const valueFor = key => b[key] === undefined ? (existingRow?.[key] ?? null) : b[key];
    const vals = {
      subgroup: valueFor('subgroup'),
      missed_lectures: valueFor('missed_lectures'),
      missed_practicals: valueFor('missed_practicals'),
      admission: valueFor('admission'),
      model_detail_level: valueFor('model_detail_level'),
      model_originality: valueFor('model_originality'),
      model_files_on_disk: valueFor('model_files_on_disk'),
      bonus_render: valueFor('bonus_render'),
      bonus_animation: valueFor('bonus_animation'),
      bonus_interesting_model: valueFor('bonus_interesting_model'),
      has_guides: valueFor('has_guides'),
      dashboard_blocks: valueFor('dashboard_blocks'),
      chart_errors: valueFor('chart_errors'),
      bonus_design: valueFor('bonus_design'),
      bonus_program_implementation: valueFor('bonus_program_implementation'),
      defense_score: valueFor('defense_score'),
      total_score: valueFor('total_score'),
      grade: valueFor('grade'),
      fact: valueFor('fact')
    };

    const params = [
      vals.subgroup, vals.missed_lectures, vals.missed_practicals, vals.admission,
      vals.model_detail_level, vals.model_originality, vals.model_files_on_disk,
      vals.bonus_render, vals.bonus_animation, vals.bonus_interesting_model,
      vals.has_guides, vals.dashboard_blocks, vals.chart_errors,
      vals.bonus_design, vals.bonus_program_implementation,
      vals.defense_score, vals.total_score, vals.grade, vals.fact
    ];

    if (existingRow) {
      await db.run(`UPDATE evaluation_results SET
        subgroup = ?, missed_lectures = ?, missed_practicals = ?, admission = ?,
        model_detail_level = ?, model_originality = ?, model_files_on_disk = ?,
        bonus_render = ?, bonus_animation = ?, bonus_interesting_model = ?,
        has_guides = ?, dashboard_blocks = ?, chart_errors = ?,
        bonus_design = ?, bonus_program_implementation = ?,
        defense_score = ?, total_score = ?, grade = ?, fact = ?
        WHERE program_id = ? AND student_id = ?`,
        [...params, programId, b.student_id]);
    } else {
      await db.run(`INSERT INTO evaluation_results
        (program_id, student_id, subgroup, missed_lectures, missed_practicals, admission,
        model_detail_level, model_originality, model_files_on_disk,
        bonus_render, bonus_animation, bonus_interesting_model,
        has_guides, dashboard_blocks, chart_errors,
        bonus_design, bonus_program_implementation,
        defense_score, total_score, grade, fact) VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [programId, b.student_id, ...params]);
    }
    res.json({ success: true });
  });

  // Publish evaluation results for a group
  app.post('/api/evaluation/publish', requireRole('supervisor'), async (req, res) => {
    const { program_id, group_name } = req.body;
    if (!program_id || !group_name) return res.status(400).json({ success: false, message: 'program_id и group_name обязательны' });
    await db.run(`UPDATE evaluation_results SET published = 1 WHERE program_id = ? AND student_id IN (SELECT id FROM users WHERE group_name = ?)`,
      [program_id, group_name]);
    res.json({ success: true });
  });

  // Unpublish evaluation results for a group
  app.post('/api/evaluation/unpublish', requireRole('supervisor'), async (req, res) => {
    const { program_id, group_name } = req.body;
    if (!program_id || !group_name) return res.status(400).json({ success: false, message: 'program_id и group_name обязательны' });
    await db.run(`UPDATE evaluation_results SET published = 0 WHERE program_id = ? AND student_id IN (SELECT id FROM users WHERE group_name = ?)`,
      [program_id, group_name]);
    res.json({ success: true });
  });

  // Student: get published evaluation results
  app.get('/api/student/results', requireRole('student'), async (req, res) => {
    const userId = req.session.user.id;
    const rows = await db.all(`
      SELECT er.*, dp.name as program_name
      FROM evaluation_results er
      JOIN dpk_programs dp ON dp.id = er.program_id
      WHERE er.student_id = ? AND er.published = 1
      ORDER BY er.id DESC
    `, [userId]);
    res.json(rows);
  });

  app.get('/api/student/attendance', requireRole('student'), async (req, res) => {
    const attendanceRows = await db.all(`
      SELECT dp.id AS program_id, dp.name AS program_name,
        COALESCE((SELECT SUM(dpt.lecture_hours) FROM dpk_program_teachers dpt WHERE dpt.program_id = dp.id AND dpt.group_name = u.group_name), 0) AS lecture_hours,
        COALESCE((SELECT SUM(dpt.practice_hours) FROM dpk_program_teachers dpt WHERE dpt.program_id = dp.id AND dpt.group_name = u.group_name), 0) AS practice_hours,
        COALESCE((SELECT SUM(dpt.lab_hours) FROM dpk_program_teachers dpt WHERE dpt.program_id = dp.id AND dpt.group_name = u.group_name), 0) AS lab_hours,
        ar.class_type, ar.class_number, ar.status
      FROM users u
      JOIN dpk_program_groups pg ON pg.group_name = u.group_name
      JOIN dpk_programs dp ON dp.id = pg.program_id
      LEFT JOIN attendance_records ar ON ar.program_id = dp.id AND ar.student_id = u.id
      WHERE u.id = ? AND u.role = 'student'
      ORDER BY dp.name,
        CASE ar.class_type WHEN 'lecture' THEN 1 WHEN 'practice' THEN 2 WHEN 'lab' THEN 3 ELSE 4 END,
        ar.class_number
    `, [req.session.user.id]);
    const programs = new Map();
    for (const row of attendanceRows) {
      if (!programs.has(row.program_id)) {
        programs.set(row.program_id, {
          program_id: row.program_id,
          program_name: row.program_name,
          lesson_counts: {
            lecture: Math.ceil((Number(row.lecture_hours) || 0) / 2),
            practice: Math.ceil((Number(row.practice_hours) || 0) / 2),
            lab: Math.ceil((Number(row.lab_hours) || 0) / 2)
          },
          records: {},
          assignments: []
        });
      }
      if (row.class_type && row.class_number) {
        const program = programs.get(row.program_id);
        program.records[`${row.class_type}_${row.class_number}`] = row.status;
        program.lesson_counts[row.class_type] = Math.max(program.lesson_counts[row.class_type] || 0, Number(row.class_number));
      }
    }

    const assignmentRows = await db.all(`
      SELECT aa.id, aa.program_id, aa.assignment_number, aar.status
      FROM attendance_assignments aa
      JOIN users u ON u.id = ? AND u.role = 'student'
      JOIN dpk_program_groups pg ON pg.program_id = aa.program_id AND pg.group_name = u.group_name
      LEFT JOIN attendance_assignment_records aar ON aar.assignment_id = aa.id AND aar.student_id = u.id
      WHERE aa.group_name = '' OR aa.group_name = u.group_name
      ORDER BY aa.program_id, aa.assignment_number
    `, [req.session.user.id]);
    for (const assignment of assignmentRows) {
      const program = programs.get(assignment.program_id);
      if (program) program.assignments.push({ id: assignment.id, status: assignment.status || '' });
    }
    res.json([...programs.values()]);
  });

  // Get published status per group for a program
  app.get('/api/evaluation/published-status/:id', requireRole('supervisor', 'teacher'), async (req, res) => {
    const programId = req.params.id;
    if (req.session.user.role === 'teacher' && !await teacherIsEvaluator(req.session.user.id, programId)) {
      return res.status(403).json({ success: false, message: 'Нет доступа к оцениванию этой программы' });
    }
    const rows = await db.all(`
      SELECT u.group_name, MAX(er.published) as published
      FROM evaluation_results er
      JOIN users u ON u.id = er.student_id
      WHERE er.program_id = ?
      GROUP BY u.group_name
    `, [programId]);
    const groups = {};
    rows.forEach(r => { groups[r.group_name] = r.published === 1; });
    res.json({ groups });
  });

  // --- Attendance Records ---
  app.get('/api/attendance/program/:id', requireRole('supervisor', 'teacher'), async (req, res) => {
    const programId = req.params.id;
    const { course, specialty, group_name, search } = req.query;
    if (req.session.user.role === 'teacher') {
      const assigned = await db.exists(`SELECT 1 FROM dpk_program_teachers WHERE program_id = ? AND teacher_id = ? AND group_name != '' LIMIT 1`, [programId, req.session.user.id]);
      if (!assigned) return res.status(403).json({ success: false, message: 'Нет доступа к посещаемости этой программы' });
    }

    // Aggregate hours per group across ALL teachers (a group can have 2 teachers)
    let hoursSql = `SELECT group_name, SUM(lecture_hours) as lecture_hours, SUM(practice_hours) as practice_hours, SUM(lab_hours) as lab_hours FROM dpk_program_teachers WHERE program_id = ?`;
    const hoursParams = [programId];
    if (req.session.user.role === 'teacher') {
      hoursSql += ` AND group_name IN (SELECT group_name FROM dpk_program_teachers WHERE program_id = ? AND teacher_id = ?)`;
      hoursParams.push(programId, req.session.user.id);
    }
    hoursSql += ` GROUP BY group_name`;
    const groupHourRows = await db.all(hoursSql, hoursParams);
    const groupHours = {};
    for (const row of groupHourRows) {
      groupHours[row.group_name] = { lecture: row.lecture_hours || 0, practice: row.practice_hours || 0, lab: row.lab_hours || 0 };
    }

    // Fallback if no teachers assigned — take first available teacher's hours
    let defaultHours = null;
    if (!Object.keys(groupHours).length && req.session.user.role !== 'teacher') {
      const h = await db.one(`SELECT lecture_hours, practice_hours, lab_hours FROM dpk_program_teachers WHERE program_id = ? LIMIT 1`, [programId]);
      if (h) defaultHours = { lecture: h.lecture_hours || 0, practice: h.practice_hours || 0, lab: h.lab_hours || 0 };
    }

    let sql = `
      SELECT u.id as student_id, u.full_name, u.group_name,
        ar.id, ar.class_type, ar.class_number, ar.status
      FROM users u
      JOIN dpk_program_groups pg ON pg.program_id = ? AND pg.group_name = u.group_name
      LEFT JOIN attendance_records ar ON ar.student_id = u.id AND ar.program_id = ?
      WHERE u.role = 'student'`;
    const params = [programId, programId];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.program_id = ? AND dpt.teacher_id = ? AND dpt.group_name = u.group_name)`;
      params.push(programId, req.session.user.id);
    }
    if (course) { sql += ` AND u.course = ?`; params.push(course); }
    if (specialty) { sql += ` AND u.specialty = ?`; params.push(specialty); }
    if (group_name) { sql += ` AND u.group_name = ?`; params.push(group_name); }
    if (search) { sql += ` AND u.full_name LIKE ?`; params.push(`%${search}%`); }
    sql += ` ORDER BY u.group_name, u.full_name, ar.class_type, ar.class_number`;
    const rows = await db.all(sql, params);
    const map = {};
    rows.forEach(r => {
      const key = r.student_id;
      if (!map[key]) {
        map[key] = { student_id: r.student_id, full_name: r.full_name, group_name: r.group_name, records: {}, assignments: {} };
      }
      if (r.class_type) {
        map[key].records[`${r.class_type}_${r.class_number}`] = r.status;
      }
    });
    const assignments = [];
    assignments.push(...await db.all(`SELECT id, group_name, assignment_number FROM attendance_assignments WHERE program_id = ? ORDER BY assignment_number`, [programId]));

    if (assignments.length && Object.keys(map).length) {
      const records = await db.all(`
        SELECT aar.assignment_id, aar.student_id, aar.status
        FROM attendance_assignment_records aar
        JOIN attendance_assignments aa ON aa.id = aar.assignment_id
        WHERE aa.program_id = ?
      `, [programId]);
      for (const record of records) {
        if (map[record.student_id]) map[record.student_id].assignments[record.assignment_id] = record.status;
      }
    }
    res.json({ students: Object.values(map), hours: defaultHours, groupHours, assignments });
  });

  app.post('/api/attendance/program/:id/assignments', requireRole('supervisor', 'teacher'), async (req, res) => {
    const programId = Number(req.params.id);
    const groupName = String(req.body.group_name || '').trim();
    const count = Number(req.body.count);
    if (!Number.isInteger(programId)) return res.status(400).json({ success: false, message: 'Некорректная программа' });
    if (!groupName) return res.status(400).json({ success: false, message: 'Выберите группу' });
    if (!Number.isInteger(count) || count < 1 || count > 30) return res.status(400).json({ success: false, message: 'Укажите количество заданий от 1 до 30' });
    const groupExists = await db.exists(`SELECT 1 FROM dpk_program_groups WHERE program_id = ? AND group_name = ?`, [programId, groupName]);
    if (!groupExists) return res.status(404).json({ success: false, message: 'Группа не найдена в программе' });
    if (req.session.user.role === 'teacher' && !await teacherHasProgramGroup(req.session.user.id, programId, groupName)) {
      return res.status(403).json({ success: false, message: 'Нет доступа к этой группе' });
    }
    const firstAssignmentNumber = (await db.one(`SELECT COALESCE(MAX(assignment_number), 0) + 1 AS next_number FROM attendance_assignments WHERE program_id = ?`, [programId])).next_number;
    await transaction(async tx => {
      for (let index = 0; index < count; index++) {
        await tx.run(`INSERT INTO attendance_assignments (program_id, group_name, assignment_number) VALUES (?, ?, ?)`, [programId, groupName, firstAssignmentNumber + index]);
      }
    });
    res.json({ success: true, count, first_assignment_number: firstAssignmentNumber });
  });

  app.post('/api/attendance/assignment/save', requireRole('supervisor', 'teacher'), async (req, res) => {
    const assignmentId = Number(req.body.assignment_id);
    const studentId = Number(req.body.student_id);
    const status = req.body.status || '';
    if (!Number.isInteger(assignmentId) || !Number.isInteger(studentId) || (status && !['completed', 'plus', 'minus'].includes(status))) {
      return res.status(400).json({ success: false, message: 'Некорректная отметка задания' });
    }
    const assignment = await db.one(`
      SELECT aa.program_id, u.group_name
      FROM attendance_assignments aa
      JOIN dpk_program_groups pg ON pg.program_id = aa.program_id
      JOIN users u ON u.id = ? AND u.role = 'student' AND u.group_name = pg.group_name
      WHERE aa.id = ? AND (aa.group_name = '' OR aa.group_name = u.group_name) LIMIT 1
    `, [studentId, assignmentId]);
    if (!assignment) return res.status(404).json({ success: false, message: 'Задание или студент не найдены' });
    if (req.session.user.role === 'teacher' && !await teacherHasProgramGroup(req.session.user.id, assignment.program_id, assignment.group_name)) {
      return res.status(403).json({ success: false, message: 'Нет доступа к этой группе' });
    }
    if (!status) {
      await db.run(`DELETE FROM attendance_assignment_records WHERE assignment_id = ? AND student_id = ?`, [assignmentId, studentId]);
    } else {
      await db.run(`INSERT INTO attendance_assignment_records (assignment_id, student_id, status) VALUES (?, ?, ?)
        ON CONFLICT (assignment_id, student_id) DO UPDATE SET status = EXCLUDED.status`, [assignmentId, studentId, status]);
    }
    res.json({ success: true });
  });

  app.delete('/api/attendance/assignment/:id', requireRole('supervisor', 'teacher'), async (req, res) => {
    const assignmentId = Number(req.params.id);
    if (!Number.isInteger(assignmentId)) return res.status(400).json({ success: false, message: 'Некорректное задание' });
    const assignment = await db.one(`SELECT program_id, group_name FROM attendance_assignments WHERE id = ?`, [assignmentId]);
    if (!assignment) return res.status(404).json({ success: false, message: 'Задание не найдено' });
    if (req.session.user.role === 'teacher' && (!assignment.group_name || !await teacherHasProgramGroup(req.session.user.id, assignment.program_id, assignment.group_name))) {
      return res.status(403).json({ success: false, message: 'Нет доступа к этому заданию' });
    }
    await db.run(`DELETE FROM attendance_assignments WHERE id = ?`, [assignmentId]);
    res.json({ success: true });
  });

  app.get('/api/attendance/program/:id/filters', requireRole('supervisor', 'teacher'), async (req, res) => {
    if (req.session.user.role === 'teacher') {
      const assigned = await db.exists(`SELECT 1 FROM dpk_program_teachers WHERE program_id = ? AND teacher_id = ? AND group_name != '' LIMIT 1`, [req.params.id, req.session.user.id]);
      if (!assigned) return res.status(403).json({ success: false, message: 'Нет доступа к посещаемости этой программы' });
    }
    const { course, specialty } = req.query;
    let sql = `SELECT DISTINCT u.course, u.specialty, u.group_name
      FROM users u
      JOIN dpk_program_groups pg ON pg.program_id = ? AND pg.group_name = u.group_name
      WHERE u.role = 'student'`;
    const params = [req.params.id];
    if (req.session.user.role === 'teacher') {
      sql += ` AND EXISTS (SELECT 1 FROM dpk_program_teachers dpt WHERE dpt.program_id = ? AND dpt.teacher_id = ? AND dpt.group_name = u.group_name)`;
      params.push(req.params.id, req.session.user.id);
    }
    if (course) { sql += ` AND u.course = ?`; params.push(course); }
    if (specialty) { sql += ` AND u.specialty = ?`; params.push(specialty); }
    sql += ` ORDER BY u.course, u.specialty, u.group_name`;
    const rows = await db.all(sql, params);
    const courses = new Set(), specialties = new Set(), groups = new Set();
    for (const row of rows) {
      if (row.course) courses.add(row.course);
      if (row.specialty) specialties.add(row.specialty);
      if (row.group_name) groups.add(row.group_name);
    }
    res.json({ courses: [...courses], specialties: [...specialties], groups: [...groups] });
  });

  app.post('/api/attendance/save', requireRole('supervisor', 'teacher'), async (req, res) => {
    const { program_id, student_id, class_type, class_number, status } = req.body;
    if (req.session.user.role === 'teacher') {
      const student = await db.one(`SELECT group_name FROM users WHERE id = ? AND role = 'student'`, [student_id]);
      if (!student || !await teacherHasProgramGroup(req.session.user.id, program_id, student.group_name)) {
        return res.status(403).json({ success: false, message: 'Нет доступа к посещаемости этой группы' });
      }
    }
    if (!status) {
      await db.run(`DELETE FROM attendance_records WHERE program_id = ? AND student_id = ? AND class_type = ? AND class_number = ?`,
        [program_id, student_id, class_type, class_number]);
      return res.json({ success: true });
    }
    await db.run(`INSERT INTO attendance_records (program_id, student_id, class_type, class_number, status) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (program_id, student_id, class_type, class_number) DO UPDATE SET status = EXCLUDED.status`,
      [program_id, student_id, class_type, class_number, status]);
    res.json({ success: true });
  });

  app.get('/api/supervisor/workers', requireRole('supervisor'), async (req, res) => {
    const rows = await db.all(`SELECT id, full_name, login, code, title, work_type, position, department, supervisor_name, category FROM users WHERE role = 'worker' ORDER BY full_name`);
    res.json(rows);
  });

  app.get('/api/supervisor/staff/export', requireRole('supervisor'), async (req, res) => {
    const rows = await db.all(`SELECT role, login, full_name, code, title, work_type, position, department, supervisor_name, category FROM users WHERE role IN ('teacher', 'worker') ORDER BY role, full_name`);

    const ws = XLSX.utils.json_to_sheet(rows.map(row => ({
      'Тип': row.role === 'teacher' ? 'Преподаватель' : 'Сотрудник',
      'Логин': row.login,
      'ФИО': row.full_name,
      'Шифр': row.code || '',
      'Звание': row.title || '',
      'Вид работы': row.work_type || '',
      'Должность': row.position || '',
      'Подразделение': row.department || '',
      'Руководитель': row.supervisor_name || '',
      'Категория': row.category || ''
    })));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Staff');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent('Преподаватели и сотрудники.xlsx'));
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  });

  app.post('/api/supervisor/staff', requireRole('supervisor'), async (req, res) => {
    let { login, password, full_name, role, code, title, work_type, position, department, supervisor_name, category } = req.body;
    if (!full_name || !role) return res.status(400).json({ success: false, message: 'ФИО и роль обязательны' });
    if (!['teacher', 'worker', 'supervisor'].includes(role)) return res.status(400).json({ success: false, message: 'Недопустимая роль' });
    if (password && !isValidPassword(password)) return res.status(400).json({ success: false, message: 'Пароль должен содержать 8–10 латинских букв или цифр' });
    if (['teacher', 'worker'].includes(role)) {
      login = await uniqueStaffLogin(db, full_name);
    } else if (!login) {
      const prefix = role === 'teacher' ? 'p' : role === 'worker' ? 'w' : 's';
      const base = full_name.replace(/\s+/g, '').toLowerCase();
      let counter = 0;
      while (true) {
        login = prefix + base + (counter > 0 ? counter : '');
        const exists = await db.exists('SELECT id FROM users WHERE login = ?', [login]);
        if (!exists) break;
        counter++;
      }
    } else {
      if (await db.exists('SELECT id FROM users WHERE login = ?', [login])) return res.status(400).json({ success: false, message: 'Логин уже существует' });
    }
    const autoCategory = category || String(calculateCategory(position, title));
    const accountPassword = role === 'teacher' ? generatePassword() : (password || generatePassword());
    await db.run(`INSERT INTO users (login, password, password_vault, role, full_name, code, title, work_type, position, department, supervisor_name, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [login, hashPassword(accountPassword), encryptPassword(accountPassword, passwordVaultKey), role, full_name, code || null, title || null, work_type || null, position || null, department || null, supervisor_name || null, autoCategory]);
    res.json({ success: true });
  });

  app.put('/api/supervisor/staff/:id', requireRole('supervisor'), async (req, res) => {
    const { full_name, role, code, title, work_type, position, department, supervisor_name, category } = req.body;
    if (!full_name) return res.status(400).json({ success: false, message: 'ФИО обязательно' });
    const login = ['teacher', 'worker'].includes(role) ? await uniqueStaffLogin(db, full_name, Number(req.params.id)) : null;
    const autoCategory = category || String(calculateCategory(position, title));
    let sql = `UPDATE users SET ${login ? 'login = ?, ' : ''}full_name = ?, code = ?, title = ?, work_type = ?, position = ?, department = ?, supervisor_name = ?, category = ?`;
    let params = [...(login ? [login] : []), full_name, code || null, title || null, work_type || null, position || null, department || null, supervisor_name || null, autoCategory];
    sql += ` WHERE id = ? AND role IN ('teacher', 'worker', 'supervisor')`;
    params.push(req.params.id);
    await db.run(sql, params);
    res.json({ success: true });
  });

  app.delete('/api/supervisor/staff/:id', requireRole('supervisor'), async (req, res) => {
    await db.run(`DELETE FROM users WHERE id = ? AND role IN ('teacher', 'worker')`, [req.params.id]);
    res.json({ success: true });
  });

  // --- Programs ---
  const PROGRAM_TYPES = ['ДПК', 'ООП', 'ЛШ', 'Лаб'];
  app.get('/api/dpk/programs', requireRole('student', 'teacher', 'worker', 'supervisor'), async (req, res) => {
    const rows = await db.all(`
      SELECT dp.*,
        (SELECT COUNT(*) FROM dpk_program_groups pg WHERE pg.program_id = dp.id) as groups_count
      FROM dpk_programs dp ORDER BY dp.name
    `);
    res.json(rows);
  });

  app.post('/api/dpk/program', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name, program_type = 'ДПК', total_hours } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Название обязательно' });
    if (!PROGRAM_TYPES.includes(program_type)) return res.status(400).json({ success: false, message: 'Некорректный тип программы' });
    await db.run(`INSERT INTO dpk_programs (name, program_type, total_hours) VALUES (?, ?, ?)`, [name, program_type, total_hours || 0]);
    res.json({ success: true });
  });

  app.put('/api/dpk/program/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const { name, program_type = 'ДПК' } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Название обязательно' });
    if (!PROGRAM_TYPES.includes(program_type)) return res.status(400).json({ success: false, message: 'Некорректный тип программы' });
    await db.run(`UPDATE dpk_programs SET name = ?, program_type = ? WHERE id = ?`, [name, program_type, req.params.id]);
    res.json({ success: true });
  });

  app.delete('/api/dpk/program/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    await db.run(`DELETE FROM dpk_programs WHERE id = ?`, [req.params.id]);
    res.json({ success: true });
  });

  // --- DPK Program-Teachers ---
  app.get('/api/dpk/program/:id/teachers', requireRole('worker', 'supervisor', 'teacher', 'student'), async (req, res) => {
    const { group } = req.query;
    let sql = `
      SELECT dpt.*, u.full_name as teacher_name
      FROM dpk_program_teachers dpt
      LEFT JOIN users u ON dpt.teacher_id = u.id
      WHERE dpt.program_id = ?
    `;
    const params = [req.params.id];
    if (group) { sql += ` AND dpt.group_name = ?`; params.push(group); }
    sql += ` ORDER BY u.full_name`;
    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.post('/api/dpk/program/:id/teacher', requireRole('worker', 'supervisor'), async (req, res) => {
    const { teacher_id, group_name } = req.body;
    if (!teacher_id) return res.status(400).json({ success: false, message: 'Преподаватель обязателен' });
    await db.run(`INSERT INTO dpk_program_teachers (program_id, teacher_id, group_name, hours) VALUES (?, ?, ?, 0) ON CONFLICT(program_id, group_name, teacher_id) DO NOTHING`,
      [req.params.id, teacher_id, group_name || '']);
    await recalcProgramTeacherHours(req.params.id, teacher_id);
    res.json({ success: true });
  });

  app.put('/api/dpk/program/teacher/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const { hours, lecture_hours, practice_hours, lab_hours } = req.body;
    const pt = await db.one(`SELECT program_id, teacher_id FROM dpk_program_teachers WHERE id = ?`, [req.params.id]);
    if (!pt) return res.status(404).json({ success: false, message: 'Запись не найдена' });
    if (lecture_hours !== undefined || practice_hours !== undefined || lab_hours !== undefined) {
      const lh = lecture_hours ?? 0, ph = practice_hours ?? 0, labh = lab_hours ?? 0;
      await db.run(`UPDATE dpk_program_teachers SET lecture_hours = ?, practice_hours = ?, lab_hours = ?, hours = ? WHERE id = ?`,
        [lh, ph, labh, lh + ph + labh, req.params.id]);
      await recalcProgramTotalHours(pt.program_id);
    } else if (hours !== undefined) {
      await db.run(`UPDATE dpk_program_teachers SET hours = ? WHERE id = ?`, [hours, req.params.id]);
      await recalcProgramTotalHours(pt.program_id);
    } else {
      await recalcProgramTeacherHours(pt.program_id, pt.teacher_id);
    }
    res.json({ success: true });
  });

  app.delete('/api/dpk/program/teacher/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const pt = await db.one(`SELECT program_id, teacher_id, group_name FROM dpk_program_teachers WHERE id = ?`, [req.params.id]);
    if (pt) {
      await db.run(`DELETE FROM schedule_entries WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND lesson_type IS NOT NULL`, [pt.program_id, pt.teacher_id, pt.group_name]);
      await db.run(`DELETE FROM dpk_teacher_lesson_dates WHERE program_id = ? AND teacher_id = ? AND group_name = ?`, [pt.program_id, pt.teacher_id, pt.group_name]);
    }
    await db.run(`DELETE FROM dpk_program_teachers WHERE id = ?`, [req.params.id]);
    if (pt) await recalcProgramTotalHours(pt.program_id);
    res.json({ success: true });
  });

  // --- DPK Teacher Lesson Dates ---
  app.get('/api/dpk/teacher/:tid/lessons', requireRole('worker', 'supervisor'), async (req, res) => {
    const { program_id, group_name } = req.query;
    if (!program_id) return res.status(400).json({ success: false, message: 'program_id required' });
    const params = [program_id, req.params.tid];
    let sql = `SELECT * FROM dpk_teacher_lesson_dates WHERE program_id = ? AND teacher_id = ?`;
    if (group_name) { sql += ` AND group_name = ?`; params.push(group_name); }
    sql += ` ORDER BY class_type, class_number`;
    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.post('/api/dpk/teacher/:tid/lessons/generate', requireRole('worker', 'supervisor'), async (req, res) => {
    const { program_id, group_name, lecture_hours, practice_hours, lab_hours } = req.body;
    if (!program_id || !group_name) return res.status(400).json({ success: false, message: 'program_id and group_name required' });
    const teacher_id = req.params.tid;
    // Remove old lesson rows and linked schedule entries for this teacher/program/group
    await db.run(`DELETE FROM schedule_entries WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND lesson_type IS NOT NULL`,
      [program_id, teacher_id, group_name]);
    await db.run(`DELETE FROM dpk_teacher_lesson_dates WHERE program_id = ? AND teacher_id = ? AND group_name = ?`,
      [program_id, teacher_id, group_name]);

    // Generate individual lesson rows from total hours (1 row per 2 hours)
    const types = [];
    if (lecture_hours > 0) types.push({ type: 'lecture', count: Math.ceil(lecture_hours / 2) });
    if (practice_hours > 0) types.push({ type: 'practice', count: Math.ceil(practice_hours / 2) });
    if (lab_hours > 0) types.push({ type: 'lab', count: Math.ceil(lab_hours / 2) });

    for (const t of types) {
      for (let i = 1; i <= t.count; i++) {
        await db.run(`INSERT INTO dpk_teacher_lesson_dates (program_id, teacher_id, group_name, class_type, class_number, date, room, time_start, time_end) VALUES (?, ?, ?, ?, ?, NULL, NULL, '09:00', '10:30')`, [program_id, teacher_id, group_name, t.type, i]);
      }
    }

    // Update the teacher hours
    const lh = lecture_hours || 0, ph = practice_hours || 0, labh = lab_hours || 0;
    const pt = await db.one(`SELECT id FROM dpk_program_teachers WHERE program_id = ? AND teacher_id = ? AND group_name = ?`, [program_id, teacher_id, group_name]);
    if (pt) {
      await db.run(`UPDATE dpk_program_teachers SET lecture_hours = ?, practice_hours = ?, lab_hours = ?, hours = ? WHERE id = ?`,
        [lh, ph, labh, lh + ph + labh, pt.id]);
      await recalcProgramTotalHours(program_id);
    }
    res.json({ success: true });
  });

  app.put('/api/dpk/teacher/lesson/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const { date, room, time_start, time_end } = req.body;
    if (date && dayOfWeekFromDateOnly(date) === null) return res.status(400).json({ success: false, message: 'Некорректная дата' });
    // Get lesson details before updating
    const lesson = await db.one(`SELECT * FROM dpk_teacher_lesson_dates WHERE id = ?`, [req.params.id]);
    if (!lesson) return res.status(404).json({ success: false });

    const fields = [];
    const params = [];
    if (date !== undefined) { fields.push('date = ?'); params.push(date || null); }
    if (room !== undefined) { fields.push('room = ?'); params.push(room || null); }
    if (time_start !== undefined) { fields.push('time_start = ?'); params.push(time_start || null); }
    if (time_end !== undefined) { fields.push('time_end = ?'); params.push(time_end || null); }
    if (!fields.length) return res.status(400).json({ success: false, message: 'No fields to update' });
    params.push(req.params.id);
    await db.run(`UPDATE dpk_teacher_lesson_dates SET ${fields.join(', ')} WHERE id = ?`, params);

    // Sync to schedule_entries: create/update a schedule entry when date is set
    const newDate = date !== undefined ? (date || null) : lesson.date;
    const newRoom = room !== undefined ? (room || null) : lesson.room;
    const newTimeStart = time_start !== undefined ? (time_start || '09:00') : (lesson.time_start || '09:00');
    const newTimeEnd = time_end !== undefined ? (time_end || '10:30') : (lesson.time_end || '10:30');
    if (newDate) {
      const scheduleDay = dayOfWeekFromDateOnly(newDate);
      const exists = await db.exists(`SELECT id FROM schedule_entries WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND date = ? AND lesson_type = ?`, [lesson.program_id, lesson.teacher_id, lesson.group_name, newDate, `${lesson.class_type}_${lesson.class_number}`]);
      if (!exists) {
        await db.run(`INSERT INTO schedule_entries (program_id, teacher_id, group_name, room, day_of_week, time_start, time_end, date, lesson_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [lesson.program_id, lesson.teacher_id, lesson.group_name, newRoom, scheduleDay, newTimeStart, newTimeEnd, newDate, `${lesson.class_type}_${lesson.class_number}`]);
      } else {
        await db.run(`UPDATE schedule_entries SET room = ?, day_of_week = ?, time_start = ?, time_end = ? WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND date = ? AND lesson_type = ?`,
          [newRoom, scheduleDay, newTimeStart, newTimeEnd, lesson.program_id, lesson.teacher_id, lesson.group_name, newDate, `${lesson.class_type}_${lesson.class_number}`]);
      }
    }
    res.json({ success: true });
  });

  app.delete('/api/dpk/teacher/lesson/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const l = await db.one(`SELECT * FROM dpk_teacher_lesson_dates WHERE id = ?`, [req.params.id]);
    if (!l) return res.status(404).json({ success: false });
    // Delete corresponding schedule entry if it exists
    if (l.date) {
      await db.run(`DELETE FROM schedule_entries WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND date = ? AND lesson_type = ?`,
        [l.program_id, l.teacher_id, l.group_name, l.date, `${l.class_type}_${l.class_number}`]);
    }
    await db.run(`DELETE FROM dpk_teacher_lesson_dates WHERE id = ?`, [req.params.id]);
    // Recalculate teacher hours based on remaining lessons
    const counts = await db.all(`
      SELECT class_type, COUNT(*) as cnt FROM dpk_teacher_lesson_dates
      WHERE program_id = ? AND teacher_id = ? AND group_name = ?
      GROUP BY class_type
    `, [l.program_id, l.teacher_id, l.group_name]);
    let lh = 0, ph = 0, labh = 0;
    for (const row of counts) {
      if (row.class_type === 'lecture') lh = row.cnt * 2;
      else if (row.class_type === 'practice') ph = row.cnt * 2;
      else if (row.class_type === 'lab') labh = row.cnt * 2;
    }
    await db.run(`UPDATE dpk_program_teachers SET lecture_hours = ?, practice_hours = ?, lab_hours = ?, hours = ? WHERE program_id = ? AND teacher_id = ? AND group_name = ?`,
      [lh, ph, labh, lh + ph + labh, l.program_id, l.teacher_id, l.group_name]);
    await recalcProgramTotalHours(l.program_id);
    res.json({ success: true });
  });

  // --- DPK Program Groups ---
  app.get('/api/dpk/program/:id/groups', requireRole('worker', 'supervisor', 'teacher'), async (req, res) => {
    const rows = await db.all(`SELECT * FROM dpk_program_groups WHERE program_id = ? ORDER BY group_name`, [req.params.id]);
    res.json(rows);
  });

  app.post('/api/dpk/program/:id/group', requireRole('worker', 'supervisor'), async (req, res) => {
    const { group_name } = req.body;
    if (!group_name) return res.status(400).json({ success: false, message: 'Укажите группу' });
    await db.run(`INSERT INTO dpk_program_groups (program_id, group_name) VALUES (?, ?) ON CONFLICT(program_id, group_name) DO NOTHING`,
      [req.params.id, group_name]);
    res.json({ success: true });
  });

  app.delete('/api/dpk/program/group/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const g = await db.one(`SELECT program_id, group_name FROM dpk_program_groups WHERE id = ?`, [req.params.id]);
    if (g) {
      await db.run(`DELETE FROM dpk_program_teachers WHERE program_id = ? AND group_name = ?`, [g.program_id, g.group_name]);
    }
    await db.run(`DELETE FROM dpk_program_groups WHERE id = ?`, [req.params.id]);
    res.json({ success: true });
  });

  // --- DPK Program Evaluators ---
  app.get('/api/dpk/program/:id/evaluators', requireRole('worker', 'supervisor', 'teacher'), async (req, res) => {
    const rows = await db.all(`
      SELECT dpe.*, u.full_name as teacher_name
      FROM dpk_program_evaluators dpe
      LEFT JOIN users u ON dpe.teacher_id = u.id
      WHERE dpe.program_id = ?
      ORDER BY u.full_name
    `, [req.params.id]);
    res.json(rows);
  });

  app.post('/api/dpk/program/:id/evaluator', requireRole('worker', 'supervisor'), async (req, res) => {
    const { teacher_ids } = req.body;
    if (!teacher_ids || !teacher_ids.length) return res.status(400).json({ success: false, message: 'Выберите преподавателей' });
    for (const tid of teacher_ids) await db.run(`INSERT INTO dpk_program_evaluators (program_id, teacher_id) VALUES (?, ?) ON CONFLICT(program_id, teacher_id) DO NOTHING`, [req.params.id, tid]);
    res.json({ success: true });
  });

  app.delete('/api/dpk/program/evaluator/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    await db.run(`DELETE FROM dpk_program_evaluators WHERE id = ?`, [req.params.id]);
    res.json({ success: true });
  });

  // --- DPK Schedule entries ---
  app.get('/api/dpk/teacher/:tid/schedule', requireRole('worker', 'supervisor'), async (req, res) => {
    const { program_id, group_name } = req.query;
    let sql = `
      SELECT se.*, COALESCE(NULLIF(se.instructor_name, ''), u.full_name) as teacher_name, COALESCE(se.program_name, dp.name) as program_name
      FROM schedule_entries se
      LEFT JOIN users u ON se.teacher_id = u.id
      LEFT JOIN dpk_programs dp ON se.program_id = dp.id
      WHERE se.teacher_id = ?`;
    const params = [req.params.tid];
    if (program_id) { sql += ` AND se.program_id = ?`; params.push(program_id); }
    if (group_name) { sql += ` AND se.group_name = ?`; params.push(group_name); }
    sql += ` ORDER BY se.date, se.time_start`;
    const rows = await db.all(sql, params);
    res.json(rows);
  });

  // --- Schedule ---
  app.get('/api/schedule/rooms', requireRole('worker', 'supervisor'), async (req, res) => {
    const rooms = (await db.all(`SELECT DISTINCT room FROM schedule_entries WHERE room IS NOT NULL AND room != '' ORDER BY room`)).map(row => row.room);
    res.json(rooms);
  });

  app.get('/api/schedule/range', requireRole('worker', 'supervisor'), async (req, res) => {
    const today = new Date().toISOString().slice(0, 10);
    const range = await db.one(`SELECT MIN(date) AS min_date, MAX(date) AS max_date, COUNT(*) AS count FROM schedule_entries WHERE source = 'room-plans-spring-2026' AND date IS NOT NULL`) || { min_date: null, max_date: null, count: 0 };

    const nextDate = (await db.one(`SELECT MIN(date) AS target_date FROM schedule_entries WHERE source = 'room-plans-spring-2026' AND date >= ?`, [today]))?.target_date;
    res.json({ ...range, target_date: nextDate || range.max_date });
  });

  app.get('/api/schedule/rooms/:room/range', requireRole('worker', 'supervisor'), async (req, res) => {
    const room = req.params.room;
    const today = new Date().toISOString().slice(0, 10);
    const range = await db.one(`SELECT MIN(date) AS min_date, MAX(date) AS max_date, COUNT(*) AS count FROM schedule_entries WHERE room = ? AND date IS NOT NULL`, [room]) || { min_date: null, max_date: null, count: 0 };

    const nextDate = (await db.one(`SELECT MIN(date) AS target_date FROM schedule_entries WHERE room = ? AND date >= ?`, [room, today]))?.target_date;
    res.json({ ...range, target_date: nextDate || range.max_date });
  });

  app.get('/api/schedule', requireRole('student', 'teacher', 'worker', 'supervisor'), async (req, res) => {
    let sql = `
      SELECT se.*, COALESCE(NULLIF(se.instructor_name, ''), u.full_name) as teacher_name, COALESCE(se.program_name, dp.name) as program_name
      FROM schedule_entries se
      LEFT JOIN users u ON se.teacher_id = u.id
      LEFT JOIN dpk_programs dp ON se.program_id = dp.id
      WHERE 1=1
    `;
    const params = [];
    if (req.query.teacher_id) { sql += ` AND se.teacher_id = ?`; params.push(req.query.teacher_id); }
    if (req.query.room) { sql += ` AND se.room = ?`; params.push(req.query.room); }
    if (req.query.group_name) { sql += ` AND se.group_name = ?`; params.push(req.query.group_name); }
    if (req.query.start_date && req.query.end_date) {
      sql += ` AND se.date >= ? AND se.date <= ?`;
      params.push(req.query.start_date, req.query.end_date);
    }
    sql += ` ORDER BY se.day_of_week, se.time_start`;
    const rows = await db.all(sql, params);
    res.json(rows);
  });

  app.post('/api/schedule', requireRole('worker', 'supervisor'), async (req, res) => {
    const { program_id, teacher_id, group_name, room, day_of_week, time_start, time_end, date } = req.body;
    if (!teacher_id || day_of_week === undefined || !time_start || !time_end) {
      return res.status(400).json({ success: false, message: 'Заполните обязательные поля' });
    }
    const entryDate = date || null;
    const scheduleDay = entryDate ? dayOfWeekFromDateOnly(entryDate) : Number(day_of_week);
    if (scheduleDay === null) return res.status(400).json({ success: false, message: 'Некорректная дата' });
    await db.run(`INSERT INTO schedule_entries (program_id, teacher_id, group_name, room, day_of_week, time_start, time_end, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [program_id || null, teacher_id, group_name || null, room || null, scheduleDay, time_start, time_end, entryDate]);
    if (program_id) await recalcProgramTeacherHours(program_id, teacher_id);
    res.json({ success: true });
  });

  app.put('/api/schedule/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const { program_id, teacher_id, group_name, room, day_of_week, time_start, time_end, date } = req.body;
    // Get old values to recalc previous pair
    const old = await db.one(`SELECT program_id, teacher_id, lesson_type, date, group_name FROM schedule_entries WHERE id = ?`, [req.params.id]);
    const entryDate = date || null;
    const scheduleDay = entryDate ? dayOfWeekFromDateOnly(entryDate) : Number(day_of_week);
    if (scheduleDay === null) return res.status(400).json({ success: false, message: 'Некорректная дата' });
    await db.run(`UPDATE schedule_entries SET program_id = ?, teacher_id = ?, group_name = ?, room = ?, day_of_week = ?, time_start = ?, time_end = ?, date = ? WHERE id = ?`,
      [program_id || null, teacher_id, group_name || null, room || null, scheduleDay, time_start, time_end, entryDate, req.params.id]);
    // Sync back to DPK lesson if this entry has a lesson_type link
    if (old && old.lesson_type && old.program_id) {
      const lt = old.lesson_type.split('_');
      const classType = lt[0];
      const classNumber = parseInt(lt[1]);
      if (await db.exists(`SELECT id FROM dpk_teacher_lesson_dates WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND class_type = ? AND class_number = ?`, [old.program_id, old.teacher_id, old.group_name, classType, classNumber])) {
        await db.run(`UPDATE dpk_teacher_lesson_dates SET date = ?, room = ?, time_start = ?, time_end = ? WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND class_type = ? AND class_number = ?`,
          [entryDate, room || null, time_start, time_end, old.program_id, old.teacher_id, old.group_name, classType, classNumber]);
      }
    }
    // Recalc old and new pairs
    if (old && old.program_id) await recalcProgramTeacherHours(old.program_id, old.teacher_id);
    if (program_id) await recalcProgramTeacherHours(program_id, teacher_id);
    res.json({ success: true });
  });

  app.delete('/api/schedule/:id', requireRole('worker', 'supervisor'), async (req, res) => {
    const old = await db.one(`SELECT program_id, teacher_id, lesson_type, date, group_name FROM schedule_entries WHERE id = ?`, [req.params.id]);
    await db.run(`DELETE FROM schedule_entries WHERE id = ?`, [req.params.id]);
    // Sync back: clear date/room/time on the linked DPK lesson
    if (old && old.lesson_type && old.program_id) {
      const lt = old.lesson_type.split('_');
      const classType = lt[0];
      const classNumber = parseInt(lt[1]);
      await db.run(`UPDATE dpk_teacher_lesson_dates SET date = NULL, time_start = '09:00', time_end = '10:30' WHERE program_id = ? AND teacher_id = ? AND group_name = ? AND class_type = ? AND class_number = ?`,
        [old.program_id, old.teacher_id, old.group_name, classType, classNumber]);
    }
    if (old && old.program_id) await recalcProgramTeacherHours(old.program_id, old.teacher_id);
    res.json({ success: true });
  });

  // --- Schedule Excel Export ---
  app.get('/api/schedule/export', requireRole('worker', 'supervisor'), async (req, res) => {
    let sql = `
      SELECT se.*, COALESCE(NULLIF(se.instructor_name, ''), u.full_name) as teacher_name, COALESCE(se.program_name, dp.name) as program_name
      FROM schedule_entries se
      LEFT JOIN users u ON se.teacher_id = u.id
      LEFT JOIN dpk_programs dp ON se.program_id = dp.id
      WHERE 1=1
    `;
    const params = [];
    if (req.query.teacher_id) { sql += ` AND se.teacher_id = ?`; params.push(req.query.teacher_id); }
    if (req.query.room) { sql += ` AND se.room = ?`; params.push(req.query.room); }
    sql += ` ORDER BY se.day_of_week, se.time_start`;
    const rows = await db.all(sql, params);

    function fmtYMD(d) {
      return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0');
    }
    const now = new Date();
    const jsDay = now.getDay();
    const monday = new Date(now.getFullYear(), now.getMonth(), now.getDate() + (jsDay === 0 ? -6 : 1 - jsDay));

    const ws = XLSX.utils.json_to_sheet(rows.map(r => {
      let dateStr = r.date;
      if (!dateStr) {
        const d = new Date(monday);
        d.setDate(monday.getDate() + r.day_of_week);
        dateStr = fmtYMD(d);
      }
      return {
        'Программа': r.program_name || '',
        'Преподаватель': r.teacher_name || '',
        'Группа/подгруппа': r.group_name || '',
        'Дата': dateStr,
        'Время': `${r.time_start}–${r.time_end}`,
        'Аудитория': r.room || ''
      };
    }));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Schedule');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    let filename = 'Расписания';
    if (req.query.teacher_name) filename += '_' + req.query.teacher_name;
    else if (req.query.room) filename += '_аудитории ' + req.query.room;
    filename += '.xlsx';

    res.setHeader('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent(filename));
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  });

  // --- Schedule Excel Import ---
  app.post('/api/schedule/import', upload.single('file'), requireRole('worker', 'supervisor'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ success: false, message: 'Файл не загружен' });
      const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const data = XLSX.utils.sheet_to_json(sheet);

      const dayMap = { 'пн': 0, 'вт': 1, 'ср': 2, 'чт': 3, 'пт': 4, 'сб': 5, 'вс': 6, 'понедельник': 0, 'вторник': 1, 'среда': 2, 'четверг': 3, 'пятница': 4, 'суббота': 5, 'воскресенье': 6 };

      let imported = 0;
      const pairs = new Set();

      for (const row of data) {
        const programName = String(row.Программа || row.program || '').trim();
        const teacherName = String(row.Преподаватель || row.teacher || '').trim();
        const group = String(row['Группа/подгруппа'] || row.group_name || row.Группа || '').trim();
        const timeStr = String(row.Время || row.time || '').trim();
        const room = String(row.Аудитория || row.room || row.class || row.Класс || '').trim();

        if (!teacherName || !timeStr) continue;

        // Find or resolve teacher — auto-create if not found
        let teacher = await db.one(`SELECT id FROM users WHERE full_name = ? AND role = 'teacher' LIMIT 1`, [teacherName]);
        if (!teacher) {
          const login = await uniqueStaffLogin(db, teacherName);
          const generatedPassword = generatePassword();
          await db.run(`INSERT INTO users (login, password, password_vault, role, full_name, category) VALUES (?, ?, ?, 'teacher', ?, '4')`,
            [login, hashPassword(generatedPassword), encryptPassword(generatedPassword, passwordVaultKey), teacherName]);
          teacher = await db.one(`SELECT id FROM users WHERE full_name = ? AND role = 'teacher' LIMIT 1`, [teacherName]);
        }
        if (!teacher) continue;
        const teacher_id = teacher.id;

        // Find or resolve program — auto-create if not found
        let program_id = null;
        if (programName) {
          let prog = await db.one(`SELECT id FROM dpk_programs WHERE name = ? LIMIT 1`, [programName]);
          if (!prog) {
            prog = await db.one(`INSERT INTO dpk_programs (name, total_hours) VALUES (?, 0) RETURNING id`, [programName]);
          }
          if (prog) program_id = prog.id;
        }

        // Track pair for batch hours calculation
        if (program_id) pairs.add(program_id + ':' + teacher_id);

        // Parse date and day_of_week
        let day_of_week = 0;
        let date = null;

        // Convert Excel serial date number to YYYY-MM-DD
        let rawDateStr = row.Дата || row.date || row.day_of_week;
        if (typeof rawDateStr === 'number' && rawDateStr > 40000) {
          const d = new Date((rawDateStr - 25569) * 86400000);
          if (!isNaN(d.getTime())) {
            const y = d.getFullYear();
            const m = String(d.getMonth()+1).padStart(2,'0');
            const dd = String(d.getDate()).padStart(2,'0');
            rawDateStr = y + '-' + m + '-' + dd;
          }
        }
        const dateStr = String(rawDateStr || '').trim().toLowerCase();
        // Try full date first (YYYY-MM-DD)
        const dateMatch = dateStr.match(/(\d{4})-(\d{1,2})-(\d{1,2})/);
        if (dateMatch) {
          date = dateMatch[0];
          const d = new Date(date + 'T00:00');
          const jsDay = d.getDay();
          day_of_week = jsDay === 0 ? 6 : jsDay - 1;
          if (day_of_week > 6) day_of_week = 0;
        } else {
          // Try DD/MM/YYYY
          const dmMatch = dateStr.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
          if (dmMatch) {
            const dd = dmMatch[1].padStart(2,'0');
            const mm = dmMatch[2].padStart(2,'0');
            const yyyy = dmMatch[3];
            date = yyyy + '-' + mm + '-' + dd;
            const d = new Date(date + 'T00:00');
            const jsDay = d.getDay();
            day_of_week = jsDay === 0 ? 6 : jsDay - 1;
            if (day_of_week > 6) day_of_week = 0;
          } else {
            // legacy: day name or number → day_of_week
            let parsed = parseInt(dateStr);
            if (!isNaN(parsed) && parsed >= 0 && parsed <= 6) {
              day_of_week = parsed;
            } else {
              day_of_week = dayMap[dateStr];
              if (day_of_week === undefined) day_of_week = 0;
            }
            // Compute date from current week
            const now = new Date();
            const jsDay = now.getDay();
            const monday = new Date(now.getFullYear(), now.getMonth(), now.getDate() + (jsDay === 0 ? -6 : 1 - jsDay));
            const d = new Date(monday);
            d.setDate(monday.getDate() + day_of_week);
            const y = d.getFullYear();
            const m = String(d.getMonth()+1).padStart(2,'0');
            const dd = String(d.getDate()).padStart(2,'0');
            date = y + '-' + m + '-' + dd;
          }
        }

        // Parse time
        let time_start = '', time_end = '';
        const timeMatch = timeStr.match(/(\d{1,2}:\d{2})\s*[–\-to]*\s*(\d{1,2}:\d{2})/i);
        if (timeMatch) {
          time_start = timeMatch[1];
          time_end = timeMatch[2];
        } else if (timeStr.match(/^\d{1,2}:\d{2}$/)) {
          time_start = timeStr;
          const [h, m] = timeStr.split(':').map(Number);
          time_end = `${String(h + 1).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
        } else {
          continue;
        }

        const bindVals = [program_id, teacher_id, group || null, room || null, day_of_week, time_start, time_end, date];
        await db.run(`INSERT INTO schedule_entries (program_id, teacher_id, group_name, room, day_of_week, time_start, time_end, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, bindVals);
        imported++;
      }

      // Batch upsert program-teacher links with hours = entries × 2
      for (const pair of pairs) {
        const [pid, tid] = pair.split(':').map(Number);
        await recalcProgramTeacherHours(pid, tid);
      }

      res.json({ success: true, imported, total: data.length });
    } catch (e) {
      console.error('Import error:', e);
      res.status(400).json({ success: false, message: 'Ошибка импорта: ' + (e.message || String(e)) });
    }
  });

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
      res.status(404).json({ error: 'Not found' });
    } else {
      res.redirect('/');
    }
  });

}

let initialization;

export async function handler(req, res) {
  initialization ||= start().catch(error => {
    initialization = undefined;
    throw error;
  });
  await initialization;
  return app(req, res);
}

export { app };
export default handler;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await start();
  app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
}
