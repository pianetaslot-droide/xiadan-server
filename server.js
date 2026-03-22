const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const path = require('path');
const https = require('https');

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
        note TEXT DEFAULT '',
        customer_name TEXT DEFAULT ''
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
// Migrazione colonne su DB esistenti
try { db.exec('ALTER TABLE licenses ADD COLUMN is_trial INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec("ALTER TABLE licenses ADD COLUMN customer_name TEXT DEFAULT ''"); } catch(e) {}
try { db.exec("ALTER TABLE licenses ADD COLUMN max_barcodes INTEGER DEFAULT 100"); } catch(e) {}
try { db.exec("ALTER TABLE licenses ADD COLUMN can_export INTEGER DEFAULT 0"); } catch(e) {}
try { db.exec("ALTER TABLE licenses ADD COLUMN can_download_images INTEGER DEFAULT 0"); } catch(e) {}

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
        return res.json({ valid: true, msg: '激活成功', expires_at: row.expires_at, max_barcodes: row.max_barcodes || 100, can_export: !!(row.can_export), can_download_images: !!(row.can_download_images) });
    }

    if (row.device_id !== device_id) {
        log('wrong_device');
        return res.json({ valid: false, msg: '此序列号已绑定其他设备' });
    }

    log('ok');
    return res.json({ valid: true, msg: '验证通过', expires_at: row.expires_at, is_trial: row.is_trial === 1, max_barcodes: row.max_barcodes || 100, can_export: !!(row.can_export), can_download_images: !!(row.can_download_images) });
});

// ====== Script protetto: solo licenze valide ======
const GIST_URL = 'https://gist.githubusercontent.com/pianetaslot-droide/2b67c88036b16c0d4b91a7281748f8d4/raw/yollgo_script.js';
const SCRIPT_SECRET = process.env.SCRIPT_SECRET; // chiave AES-256 in Railway env vars
let scriptCache = { content: null, fetchedAt: 0 };
const CACHE_TTL = 5 * 60 * 1000; // 5 minuti

function fetchEncryptedScript() {
    return new Promise((resolve, reject) => {
        https.get(GIST_URL + '?t=' + Date.now(), (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data.trim()));
        }).on('error', reject);
    });
}

function decryptScript(encryptedBase64) {
    if (!SCRIPT_SECRET) throw new Error('SCRIPT_SECRET non configurato');
    const buf = Buffer.from(encryptedBase64, 'base64');
    const iv         = buf.slice(0, 12);
    const tag        = buf.slice(buf.length - 16);
    const ciphertext = buf.slice(12, buf.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(SCRIPT_SECRET, 'hex'), iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(ciphertext, null, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

app.post('/api/script', rateLimit, async (req, res) => {
    const { license_key, device_id } = req.body;
    if (!license_key || !device_id) return res.json({ valid: false, msg: '参数不完整' });

    const key = license_key.trim().toUpperCase();
    const row = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(key);

    if (!row || !row.is_active)                    return res.json({ valid: false, msg: '序列号无效' });
    if (new Date().toISOString() > row.expires_at) return res.json({ valid: false, msg: '序列号已过期' });
    if (row.device_id && row.device_id !== device_id) return res.json({ valid: false, msg: '设备不匹配' });

    try {
        const now = Date.now();
        if (!scriptCache.content || now - scriptCache.fetchedAt > CACHE_TTL) {
            const encrypted = await fetchEncryptedScript();
            scriptCache.content = decryptScript(encrypted);
            scriptCache.fetchedAt = now;
        }
        res.json({ valid: true, script: scriptCache.content });
    } catch (e) {
        console.error('Script decrypt error:', e.message);
        res.status(500).json({ valid: false, msg: '脚本加载失败，请重试' });
    }
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
        SELECT id, license_key, customer_name, device_id, created_at, expires_at, is_active, is_trial, note, max_barcodes, can_export, can_download_images,
               CASE WHEN datetime('now') > expires_at THEN 1 ELSE 0 END as is_expired
        FROM licenses ORDER BY created_at DESC LIMIT 500
    `).all();
    res.json({ total: rows.length, licenses: rows });
});

// 批量生成序列号
app.post('/api/admin/generate', requireAdmin, (req, res) => {
    const count         = Math.min(req.body.count || 1, 100);
    const days          = req.body.days || 30;
    const note          = req.body.note || '手动生成';
    const customerName  = req.body.customer_name || '';

    const expires = new Date();
    expires.setDate(expires.getDate() + days);
    const expiresAt = expires.toISOString();

    const insert = db.prepare('INSERT INTO licenses (license_key, expires_at, note, customer_name) VALUES (?, ?, ?, ?)');
    const keys = [];
    db.exec('BEGIN');
    try {
        for (let i = 0; i < count; i++) {
            const key = generateKey();
            insert.run(key, expiresAt, note, customerName);
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

// 修改客户名称
app.post('/api/admin/rename', requireAdmin, (req, res) => {
    const key  = (req.body.license_key || '').toUpperCase();
    const name = (req.body.customer_name || '').trim();
    const r = db.prepare('UPDATE licenses SET customer_name=? WHERE license_key=?').run(name, key);
    if (r.changes === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '客户名称已更新', license_key: key, customer_name: name });
});

// 设置最大条码数（100或500）
app.post('/api/admin/set-max-barcodes', requireAdmin, (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const max = parseInt(req.body.max_barcodes) || 100;
    if (![100, 500, 9999].includes(max)) return res.status(400).json({ error: '只能设置100、500或9999' });
    const r = db.prepare('UPDATE licenses SET max_barcodes=? WHERE license_key=?').run(max, key);
    if (r.changes === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: `已设置为${max}个条码`, license_key: key, max_barcodes: max });
});

// 设置导出权限
app.post('/api/admin/set-export', requireAdmin, (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const canExport = req.body.can_export ? 1 : 0;
    const r = db.prepare('UPDATE licenses SET can_export=? WHERE license_key=?').run(canExport, key);
    if (r.changes === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: canExport ? '已开启导出功能' : '已关闭导出功能', license_key: key, can_export: !!canExport });
});

// 设置图片下载权限
app.post('/api/admin/set-download-images', requireAdmin, (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const canDL = req.body.can_download_images ? 1 : 0;
    const r = db.prepare('UPDATE licenses SET can_download_images=? WHERE license_key=?').run(canDL, key);
    if (r.changes === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: canDL ? '已开启图片下载功能' : '已关闭图片下载功能', license_key: key, can_download_images: !!canDL });
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
