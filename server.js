const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ====== Rate Limiting (max 10 verify/IP/minuto) ======
const rateLimitMap = new Map();
const RATE_WINDOW = 60_000;
const RATE_MAX = 10;
const rateLimit = (req, res, next) => {
    const ip = (req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '').trim();
    const now = Date.now();
    const rec = rateLimitMap.get(ip);
    if (!rec || now > rec.resetAt) {
        rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
        return next();
    }
    rec.count++;
    if (rec.count > RATE_MAX) return res.status(429).json({ valid: false, msg: '请求过于频繁，请稍后再试' });
    next();
};
setInterval(() => { const now = Date.now(); rateLimitMap.forEach((v, k) => { if (now > v.resetAt) rateLimitMap.delete(k); }); }, 300_000);

// ====== 数据库初始化 ======
const db = new DatabaseSync(path.join(__dirname, 'licenses.db'));
db.exec('PRAGMA journal_mode = WAL');

db.exec(`
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE NOT NULL,
        device_id TEXT DEFAULT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        is_trial INTEGER DEFAULT 0,
        note TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS admin_tokens (
        token TEXT PRIMARY KEY
    );
    CREATE TABLE IF NOT EXISTS verify_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT,
        device_id TEXT,
        result TEXT,
        ip TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS trial_devices (
        device_id TEXT PRIMARY KEY,
        created_at TEXT DEFAULT (datetime('now'))
    );
`);
// Migrazione colonna is_trial su DB esistenti
try { db.exec('ALTER TABLE licenses ADD COLUMN is_trial INTEGER DEFAULT 0'); } catch(e) {}

// ====== 管理员密钥（首次运行自动生成） ======
let adminRow = db.prepare('SELECT token FROM admin_tokens LIMIT 1').get();
if (!adminRow) {
    const adminToken = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO admin_tokens (token) VALUES (?)').run(adminToken);
    adminRow = { token: adminToken };
}
console.log('\n========================================');
console.log('管理员密钥：');
console.log(adminRow.token);
console.log('========================================\n');

// ====== 中间件：管理员鉴权 ======
const requireAdmin = (req, res, next) => {
    const token = req.headers['x-admin-token'];
    if (!token) return res.status(401).json({ error: '缺少管理员密钥' });
    const row = db.prepare('SELECT token FROM admin_tokens WHERE token = ?').get(token);
    if (!row) return res.status(403).json({ error: '密钥无效' });
    next();
};

// ====== 生成序列号 ======
function generateKey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const seg = () => Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
    return `XDSQ-${seg()}-${seg()}-${seg()}`;
}

// ==========================================
//  APP 端接口
// ==========================================

app.post('/api/verify', rateLimit, (req, res) => {
    const { license_key, device_id } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!license_key || !device_id) return res.json({ valid: false, msg: '参数不完整' });

    const key = license_key.trim().toUpperCase();
    const row = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(key);

    const log = (result) => {
        db.prepare('INSERT INTO verify_log (license_key, device_id, result, ip) VALUES (?, ?, ?, ?)').run(key, device_id, result, ip);
    };

    if (!row)           { log('not_found');   return res.json({ valid: false, msg: '序列号不存在' }); }
    if (!row.is_active) { log('disabled');    return res.json({ valid: false, msg: '序列号已被禁用' }); }

    if (new Date().toISOString() > row.expires_at) {
        log('expired');
        return res.json({ valid: false, msg: '序列号已过期，请续费', expired: true });
    }

    if (!row.device_id) {
        db.prepare('UPDATE licenses SET device_id = ? WHERE license_key = ?').run(device_id, key);
        log('bound_new');
        return res.json({ valid: true, msg: '激活成功', expires_at: row.expires_at });
    }

    if (row.device_id !== device_id) {
        log('wrong_device');
        return res.json({ valid: false, msg: '此序列号已绑定其他设备' });
    }

    log('ok');
    return res.json({ valid: true, msg: '验证通过', expires_at: row.expires_at, is_trial: row.is_trial === 1 });
});

// ====== Trial 1 ora (una volta per dispositivo) ======
app.post('/api/trial', rateLimit, (req, res) => {
    const { device_id } = req.body;
    if (!device_id) return res.json({ valid: false, msg: '参数不完整' });

    const used = db.prepare('SELECT device_id FROM trial_devices WHERE device_id = ?').get(device_id);
    if (used) return res.json({ valid: false, msg: '每台设备只能免费试用一次', trial_used: true });

    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const seg = () => Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
    const trialKey = `TRIA-${seg()}-${seg()}-${seg()}`;
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 ora

    db.exec('BEGIN');
    try {
        db.prepare('INSERT INTO licenses (license_key, expires_at, is_trial, note, device_id) VALUES (?, ?, 1, ?, ?)').run(trialKey, expires.toISOString(), '免费试用1小时', device_id);
        db.prepare('INSERT INTO trial_devices (device_id) VALUES (?)').run(device_id);
        db.exec('COMMIT');
    } catch(e) {
        db.exec('ROLLBACK');
        return res.status(500).json({ valid: false, msg: '生成试用失败，请重试' });
    }
    return res.json({ valid: true, license_key: trialKey, expires_at: expires.toISOString(), msg: '试用激活成功，有效1小时', is_trial: true });
});

// ==========================================
//  管理后台接口
// ==========================================

// 统计
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const total      = db.prepare('SELECT COUNT(*) as c FROM licenses').get().c;
    const active     = db.prepare("SELECT COUNT(*) as c FROM licenses WHERE is_active=1 AND datetime('now') <= expires_at AND is_trial=0").get().c;
    const trials     = db.prepare('SELECT COUNT(*) as c FROM trial_devices').get().c;
    const expired    = db.prepare("SELECT COUNT(*) as c FROM licenses WHERE datetime('now') > expires_at").get().c;
    const disabled   = db.prepare('SELECT COUNT(*) as c FROM licenses WHERE is_active=0').get().c;
    const todayVerif = db.prepare("SELECT COUNT(*) as c FROM verify_log WHERE date(created_at)=date('now')").get().c;
    res.json({ total, active, trials, expired, disabled, today_verifies: todayVerif });
});

// 查看所有序列号
app.get('/api/admin/licenses', requireAdmin, (req, res) => {
    const rows = db.prepare(`
        SELECT id, license_key, device_id, created_at, expires_at, is_active, note,
               CASE WHEN datetime('now') > expires_at THEN 1 ELSE 0 END as is_expired
        FROM licenses ORDER BY created_at DESC LIMIT 500
    `).all();
    res.json({ total: rows.length, licenses: rows });
});

// 批量生成序列号
app.post('/api/admin/generate', requireAdmin, (req, res) => {
    const count = Math.min(req.body.count || 1, 100);
    const days  = req.body.days || 30;
    const note  = req.body.note || '手动生成';

    const expires = new Date();
    expires.setDate(expires.getDate() + days);
    const expiresAt = expires.toISOString();

    const insert = db.prepare('INSERT INTO licenses (license_key, expires_at, note) VALUES (?, ?, ?)');
    const keys = [];
    db.exec('BEGIN');
    try {
        for (let i = 0; i < count; i++) {
            const key = generateKey();
            insert.run(key, expiresAt, note);
            keys.push(key);
        }
        db.exec('COMMIT');
    } catch (e) {
        db.exec('ROLLBACK');
        throw e;
    }

    res.json({ msg: `已生成 ${count} 个序列号，有效 ${days} 天`, expires_at: expiresAt, keys });
});

// 禁用
app.post('/api/admin/disable', requireAdmin, (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const r = db.prepare('UPDATE licenses SET is_active=0 WHERE license_key=?').run(key);
    if (r.changes === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '已禁用', license_key: key });
});

// 启用
app.post('/api/admin/enable', requireAdmin, (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const r = db.prepare('UPDATE licenses SET is_active=1 WHERE license_key=?').run(key);
    if (r.changes === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '已启用', license_key: key });
});

// 续费
app.post('/api/admin/renew', requireAdmin, (req, res) => {
    const key  = (req.body.license_key || '').toUpperCase();
    const days = req.body.days || 30;
    const row  = db.prepare('SELECT * FROM licenses WHERE license_key=?').get(key);
    if (!row) return res.status(404).json({ error: '序列号不存在' });

    const base = new Date(Math.max(new Date(row.expires_at).getTime(), Date.now()));
    base.setDate(base.getDate() + days);
    db.prepare('UPDATE licenses SET expires_at=?, is_active=1 WHERE license_key=?').run(base.toISOString(), key);
    res.json({ msg: `已续费 ${days} 天`, license_key: key, new_expires_at: base.toISOString() });
});

// 解绑设备
app.post('/api/admin/unbind', requireAdmin, (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const r = db.prepare('UPDATE licenses SET device_id=NULL WHERE license_key=?').run(key);
    if (r.changes === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '已解绑设备', license_key: key });
});

// ====== Pannello Admin ======
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ====== Avvio ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n下单神器验证服务运行中: http://localhost:${PORT}`);
    console.log(`管理后台: http://localhost:${PORT}/admin`);
});
