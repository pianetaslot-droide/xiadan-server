const express = require('express');
const { createClient } = require('@libsql/client');
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

// ====== Database (Turso hosted SQLite) ======
const db = createClient({
    url: process.env.TURSO_URL || 'file:licenses.db',
    authToken: process.env.TURSO_AUTH_TOKEN
});

// Helper: esegui query e ritorna prima riga
async function dbGet(sql, args = []) {
    const r = await db.execute({ sql, args });
    return r.rows[0] || null;
}
// Helper: esegui query e ritorna tutte le righe
async function dbAll(sql, args = []) {
    const r = await db.execute({ sql, args });
    return r.rows;
}
// Helper: esegui query senza ritorno
async function dbRun(sql, args = []) {
    return await db.execute({ sql, args });
}

async function initDB() {
    await dbRun(`CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE NOT NULL,
        device_id TEXT DEFAULT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        is_trial INTEGER DEFAULT 0,
        note TEXT DEFAULT '',
        customer_name TEXT DEFAULT ''
    )`);
    await dbRun(`CREATE TABLE IF NOT EXISTS admin_tokens (token TEXT PRIMARY KEY)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS verify_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT,
        device_id TEXT,
        result TEXT,
        ip TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )`);
    await dbRun(`CREATE TABLE IF NOT EXISTS trial_devices (
        device_id TEXT PRIMARY KEY,
        created_at TEXT DEFAULT (datetime('now'))
    )`);

    // Migrazioni colonne (ignora errori se esistono già)
    const migrations = [
        "ALTER TABLE licenses ADD COLUMN is_trial INTEGER DEFAULT 0",
        "ALTER TABLE licenses ADD COLUMN customer_name TEXT DEFAULT ''",
        "ALTER TABLE licenses ADD COLUMN max_barcodes INTEGER DEFAULT 100",
        "ALTER TABLE licenses ADD COLUMN can_export INTEGER DEFAULT 0",
        "ALTER TABLE licenses ADD COLUMN can_download_images INTEGER DEFAULT 0",
        "ALTER TABLE licenses ADD COLUMN can_scrape_products INTEGER DEFAULT 0"
    ];
    for (const sql of migrations) {
        try { await dbRun(sql); } catch(e) {}
    }

    // Admin token
    let adminRow = await dbGet('SELECT token FROM admin_tokens LIMIT 1');
    if (!adminRow) {
        const adminToken = crypto.randomBytes(32).toString('hex');
        await dbRun('INSERT INTO admin_tokens (token) VALUES (?)', [adminToken]);
        adminRow = { token: adminToken };
    }
    console.log('\n========================================');
    console.log('管理员密钥：');
    console.log(adminRow.token);
    console.log('========================================\n');
}

// ====== 中间件：管理员鉴权 ======
const requireAdmin = async (req, res, next) => {
    const token = req.headers['x-admin-token'];
    if (!token) return res.status(401).json({ error: '缺少管理员密钥' });
    const row = await dbGet('SELECT token FROM admin_tokens WHERE token = ?', [token]);
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

app.post('/api/verify', rateLimit, async (req, res) => {
    const { license_key, device_id } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (!license_key || !device_id) return res.json({ valid: false, msg: '参数不完整' });

    const key = license_key.trim().toUpperCase();
    const row = await dbGet('SELECT * FROM licenses WHERE license_key = ?', [key]);

    const log = async (result) => {
        await dbRun('INSERT INTO verify_log (license_key, device_id, result, ip) VALUES (?, ?, ?, ?)', [key, device_id, result, ip]);
    };

    if (!row)           { await log('not_found');  return res.json({ valid: false, msg: '序列号不存在' }); }
    if (!row.is_active) { await log('disabled');   return res.json({ valid: false, msg: '序列号已被禁用' }); }
    if (new Date().toISOString() > row.expires_at) {
        await log('expired');
        return res.json({ valid: false, msg: '序列号已过期，请续费', expired: true });
    }

    if (!row.device_id) {
        await dbRun('UPDATE licenses SET device_id = ? WHERE license_key = ?', [device_id, key]);
        await log('bound_new');
        return res.json({ valid: true, msg: '激活成功', expires_at: row.expires_at, max_barcodes: row.max_barcodes || 100, can_export: !!(row.can_export), can_download_images: !!(row.can_download_images), can_scrape_products: !!(row.can_scrape_products) });
    }

    if (row.device_id !== device_id) {
        await log('wrong_device');
        return res.json({ valid: false, msg: '此序列号已绑定其他设备' });
    }

    await log('ok');
    return res.json({ valid: true, msg: '验证通过', expires_at: row.expires_at, is_trial: row.is_trial === 1, max_barcodes: row.max_barcodes || 100, can_export: !!(row.can_export), can_download_images: !!(row.can_download_images), can_scrape_products: !!(row.can_scrape_products) });
});

// ====== Script protetto: solo licenze valide ======
const SCRIPT_SECRET = process.env.SCRIPT_SECRET;
const SCRIPT_FILE = path.join(__dirname, 'encrypted_script.b64');
let scriptCache = { content: null, fetchedAt: 0 };
const CACHE_TTL = 5 * 60 * 1000;

function fetchEncryptedScript() {
    return new Promise((resolve, reject) => {
        try {
            const data = require('fs').readFileSync(SCRIPT_FILE, 'utf8').trim();
            resolve(data);
        } catch (e) {
            reject(new Error('Script file not found: ' + e.message));
        }
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
    const row = await dbGet('SELECT * FROM licenses WHERE license_key = ?', [key]);

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

// ====== Trial 1 ora ======
app.post('/api/trial', rateLimit, async (req, res) => {
    const { device_id } = req.body;
    if (!device_id) return res.json({ valid: false, msg: '参数不完整' });

    const used = await dbGet('SELECT device_id FROM trial_devices WHERE device_id = ?', [device_id]);
    if (used) return res.json({ valid: false, msg: '每台设备只能免费试用一次', trial_used: true });

    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const seg = () => Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
    const trialKey = `TRIA-${seg()}-${seg()}-${seg()}`;
    const expires = new Date(Date.now() + 60 * 60 * 1000);

    try {
        await db.batch([
            { sql: 'INSERT INTO licenses (license_key, expires_at, is_trial, note, device_id) VALUES (?, ?, 1, ?, ?)', args: [trialKey, expires.toISOString(), '免费试用1小时', device_id] },
            { sql: 'INSERT INTO trial_devices (device_id) VALUES (?)', args: [device_id] }
        ], 'write');
    } catch(e) {
        return res.status(500).json({ valid: false, msg: '生成试用失败，请重试' });
    }
    return res.json({ valid: true, license_key: trialKey, expires_at: expires.toISOString(), msg: '试用激活成功，有效1小时', is_trial: true });
});

// ==========================================
//  管理后台接口
// ==========================================

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    const total      = (await dbGet("SELECT COUNT(*) as c FROM licenses")).c;
    const active     = (await dbGet("SELECT COUNT(*) as c FROM licenses WHERE is_active=1 AND datetime('now') <= expires_at AND is_trial=0")).c;
    const trials     = (await dbGet('SELECT COUNT(*) as c FROM trial_devices')).c;
    const expired    = (await dbGet("SELECT COUNT(*) as c FROM licenses WHERE datetime('now') > expires_at")).c;
    const disabled   = (await dbGet('SELECT COUNT(*) as c FROM licenses WHERE is_active=0')).c;
    const todayVerif = (await dbGet("SELECT COUNT(*) as c FROM verify_log WHERE date(created_at)=date('now')")).c;
    res.json({ total, active, trials, expired, disabled, today_verifies: todayVerif });
});

app.get('/api/admin/licenses', requireAdmin, async (req, res) => {
    const rows = await dbAll(`
        SELECT id, license_key, customer_name, device_id, created_at, expires_at, is_active, is_trial, note, max_barcodes, can_export, can_download_images, can_scrape_products,
               CASE WHEN datetime('now') > expires_at THEN 1 ELSE 0 END as is_expired
        FROM licenses ORDER BY created_at DESC LIMIT 500
    `);
    res.json({ total: rows.length, licenses: rows });
});

app.post('/api/admin/generate', requireAdmin, async (req, res) => {
    const count        = Math.min(req.body.count || 1, 100);
    const days         = req.body.days || 30;
    const note         = req.body.note || '手动生成';
    const customerName = req.body.customer_name || '';

    const expires = new Date();
    expires.setDate(expires.getDate() + days);
    const expiresAt = expires.toISOString();

    const keys = [];
    const stmts = [];
    for (let i = 0; i < count; i++) {
        const key = generateKey();
        keys.push(key);
        stmts.push({ sql: 'INSERT INTO licenses (license_key, expires_at, note, customer_name) VALUES (?, ?, ?, ?)', args: [key, expiresAt, note, customerName] });
    }
    await db.batch(stmts, 'write');
    res.json({ msg: `已生成 ${count} 个序列号，有效 ${days} 天`, expires_at: expiresAt, keys });
});

app.post('/api/admin/disable', requireAdmin, async (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const r = await dbRun('UPDATE licenses SET is_active=0 WHERE license_key=?', [key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '已禁用', license_key: key });
});

app.post('/api/admin/enable', requireAdmin, async (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const r = await dbRun('UPDATE licenses SET is_active=1 WHERE license_key=?', [key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '已启用', license_key: key });
});

app.post('/api/admin/renew', requireAdmin, async (req, res) => {
    const key  = (req.body.license_key || '').toUpperCase();
    const days = req.body.days || 30;
    const row  = await dbGet('SELECT * FROM licenses WHERE license_key=?', [key]);
    if (!row) return res.status(404).json({ error: '序列号不存在' });

    const base = new Date(Math.max(new Date(row.expires_at).getTime(), Date.now()));
    base.setDate(base.getDate() + days);
    await dbRun('UPDATE licenses SET expires_at=?, is_active=1 WHERE license_key=?', [base.toISOString(), key]);
    res.json({ msg: `已续费 ${days} 天`, license_key: key, new_expires_at: base.toISOString() });
});

app.post('/api/admin/rename', requireAdmin, async (req, res) => {
    const key  = (req.body.license_key || '').toUpperCase();
    const name = (req.body.customer_name || '').trim();
    const r = await dbRun('UPDATE licenses SET customer_name=? WHERE license_key=?', [name, key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '客户名称已更新', license_key: key, customer_name: name });
});

app.post('/api/admin/set-max-barcodes', requireAdmin, async (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const max = parseInt(req.body.max_barcodes) || 100;
    if (![100, 500, 9999].includes(max)) return res.status(400).json({ error: '只能设置100、500或9999' });
    const r = await dbRun('UPDATE licenses SET max_barcodes=? WHERE license_key=?', [max, key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: `已设置为${max}个条码`, license_key: key, max_barcodes: max });
});

app.post('/api/admin/set-export', requireAdmin, async (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const canExport = req.body.can_export ? 1 : 0;
    const r = await dbRun('UPDATE licenses SET can_export=? WHERE license_key=?', [canExport, key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: canExport ? '已开启导出功能' : '已关闭导出功能', license_key: key, can_export: !!canExport });
});

app.post('/api/admin/set-download-images', requireAdmin, async (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const canDL = req.body.can_download_images ? 1 : 0;
    const r = await dbRun('UPDATE licenses SET can_download_images=? WHERE license_key=?', [canDL, key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: canDL ? '已开启图片下载功能' : '已关闭图片下载功能', license_key: key, can_download_images: !!canDL });
});

app.post('/api/admin/set-scrape-products', requireAdmin, async (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const canScrape = req.body.can_scrape_products ? 1 : 0;
    const r = await dbRun('UPDATE licenses SET can_scrape_products=? WHERE license_key=?', [canScrape, key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: canScrape ? '已开启抓取功能' : '已关闭抓取功能', license_key: key, can_scrape_products: !!canScrape });
});

app.post('/api/admin/unbind', requireAdmin, async (req, res) => {
    const key = (req.body.license_key || '').toUpperCase();
    const r = await dbRun('UPDATE licenses SET device_id=NULL WHERE license_key=?', [key]);
    if (r.rowsAffected === 0) return res.status(404).json({ error: '序列号不存在' });
    res.json({ msg: '已解绑设备', license_key: key });
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ====== Avvio ======
const PORT = process.env.PORT || 3000;
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`下单神器验证服务运行中: http://localhost:${PORT}`);
        console.log(`管理后台: http://localhost:${PORT}/admin`);
    });
}).catch(err => {
    console.error('DB init failed:', err);
    process.exit(1);
});
