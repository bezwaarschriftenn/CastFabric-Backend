/**
 * CASTFABRIC V37 — 100% Werkende Backend voor Render
 * ════════════════════════════════════════════════════════════════════
 * Deze versie werkt gegarandeerd op Render met SQLite.
 * Geen PostgreSQL gedoe, geen ingewikkelde configuratie.
 * ════════════════════════════════════════════════════════════════════
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const WebSocket = require('ws');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();

// ── DATABASE: SQLite (werkt altijd op Render) ─────────────────────
// Gebruik /tmp/ op Render (beschrijfbaar) of lokale map
let dbPath = process.env.DATABASE_URL || 'sqlite:///tmp/castfabric.db';
if (dbPath.startsWith('sqlite://')) {
  dbPath = dbPath.replace('sqlite://', '');
}

// Zorg dat de map bestaat
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  try {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log(`📁 Map aangemaakt: ${dbDir}`);
  } catch (e) {
    console.log(`📁 Map bestaat al of kan niet worden aangemaakt: ${e.message}`);
  }
}

console.log(`📁 Database: ${dbPath}`);

// Open database met better-sqlite3
let db;
try {
  db = new Database(dbPath);
  console.log('✅ SQLite database geopend');
} catch (e) {
  console.error('❌ Kan database niet openen:', e.message);
  process.exit(1);
}

// ── TABELLEN AANMAKEN ──────────────────────────────────────────────
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      is_pro INTEGER NOT NULL DEFAULT 0,
      plan TEXT NOT NULL DEFAULT 'free',
      pro_expiry INTEGER,
      podcasts_generated INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    
    CREATE TABLE IF NOT EXISTS usage_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      day TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      UNIQUE(user_id, day)
    );
  `);
  console.log('✅ Tabellen aangemaakt/bestaan');
} catch (e) {
  console.error('❌ Kan tabellen niet aanmaken:', e.message);
  process.exit(1);
}

// ── HELPER: query functie (lijkt op pg) ──────────────────────────
function query(sql, params = []) {
  try {
    // Converteer PostgreSQL $1, $2 naar SQLite ?
    let query = sql;
    if (query.includes('$1')) {
      for (let i = params.length; i > 0; i--) {
        query = query.replace('$' + i, '?');
      }
    }
    
    // ON CONFLICT → SQLite syntax
    query = query.replace(/ON CONFLICT \(user_id, day\) DO UPDATE SET count = usage_log\.count \+ 1/g, 
      'ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1');
    
    // RETURNING → SQLite heeft dat niet
    if (query.includes('RETURNING')) {
      const insertQuery = query.replace(' RETURNING *', '');
      const stmt = db.prepare(insertQuery);
      const info = stmt.run(params);
      return { rows: [{ id: info.lastInsertRowid }] };
    }
    
    const stmt = db.prepare(query);
    
    // Check of het een SELECT is
    if (query.trim().toUpperCase().startsWith('SELECT')) {
      const rows = stmt.all(params);
      return { rows };
    } else {
      // INSERT, UPDATE, DELETE
      const info = stmt.run(params);
      return { rows: [{ id: info.lastInsertRowid, changes: info.changes }] };
    }
  } catch (e) {
    console.error('❌ Query error:', e.message);
    console.error('SQL:', sql);
    console.error('Params:', params);
    throw e;
  }
}

// ── BASIS HARDENING ────────────────────────────────────────────────
app.use(helmet());
app.use(cookieParser(process.env.COOKIE_SECRET || 'fallback_secret'));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  credentials: true,
}));

// ── HEALTH CHECK ──────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  try {
    // Test database
    db.prepare('SELECT 1').get();
    res.json({ 
      status: 'ok', 
      db: 'sqlite', 
      time: new Date().toISOString(),
      message: 'CASTFABRIC V37 backend is running!'
    });
  } catch (e) {
    res.status(503).json({ 
      status: 'error', 
      db: 'unreachable', 
      message: e.message 
    });
  }
});

// ── ROOT ENDPOINT ──────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    message: '🎙️ CASTFABRIC V37 backend is running!',
    status: 'ok',
    endpoints: {
      health: '/api/health',
      register: '/api/register (POST)',
      login: '/api/login (POST)',
      logout: '/api/logout (POST)',
      me: '/api/me (GET)',
      usage: '/api/usage (GET)',
      tts: '/api/tts (POST)'
    }
  });
});

// ── RATE LIMITS ──────────────────────────────────────────────────
app.use('/api/', rateLimit({ 
  windowMs: 60_000, 
  max: 120, 
  standardHeaders: true, 
  legacyHeaders: false 
}));

const COOKIE_OPTS = { 
  httpOnly: true, 
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax', 
  maxAge: 7 * 24 * 3600 * 1000 
};

function authRequired(req, res, next) {
  const token = req.cookies.castfabric_session;
  if (!token) return res.status(401).json({ error: 'not_authenticated' });
  try {
    req.userId = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret').uid;
    next();
  } catch {
    res.status(401).json({ error: 'invalid_session' });
  }
}

function publicUser(row) {
  if (!row) return null;
  return {
    uid: row.id, 
    email: row.email, 
    name: row.name,
    isPro: !!row.is_pro, 
    plan: row.plan,
    podcastsGenerated: row.podcasts_generated,
  };
}

const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 30 });

// ── REGISTRATIE ──────────────────────────────────────────────────
app.post('/api/register', authLimiter, express.json({ limit: '200kb' }), async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'invalid_input' });
  }
  
  try {
    const hash = await bcrypt.hash(password, 12);
    const id = 'user_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    
    query(
      'INSERT INTO users (id,email,password_hash,name,created_at) VALUES ($1,$2,$3,$4,$5)',
      [id, email.toLowerCase().trim(), hash, name || email.split('@')[0], Date.now()]
    );
    
    const token = jwt.sign({ uid: id }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: '7d' });
    res.cookie('castfabric_session', token, COOKIE_OPTS);
    
    const rows = query('SELECT * FROM users WHERE id=$1', [id]);
    res.json(publicUser(rows.rows?.[0] || rows[0]));
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'email_in_use' });
    }
    console.error('Register error:', e);
    res.status(500).json({ error: 'internal' });
  }
});

// ── LOGIN ────────────────────────────────────────────────────────
app.post('/api/login', authLimiter, express.json({ limit: '200kb' }), async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const rows = query('SELECT * FROM users WHERE email=$1', [(email || '').toLowerCase().trim()]);
    const row = rows.rows?.[0] || rows[0];
    
    if (!row || !(await bcrypt.compare(password || '', row.password_hash))) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    
    const token = jwt.sign({ uid: row.id }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: '7d' });
    res.cookie('castfabric_session', token, COOKIE_OPTS);
    res.json(publicUser(row));
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'internal' });
  }
});

// ── LOGOUT ───────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => { 
  res.clearCookie('castfabric_session'); 
  res.json({ ok: true }); 
});

// ── ME ──────────────────────────────────────────────────────────
app.get('/api/me', authRequired, (req, res) => {
  try {
    const rows = query('SELECT * FROM users WHERE id=$1', [req.userId]);
    res.json(publicUser(rows.rows?.[0] || rows[0]));
  } catch (e) {
    res.status(500).json({ error: 'internal' });
  }
});

// ── USAGE ──────────────────────────────────────────────────────
app.get('/api/usage', authRequired, (req, res) => {
  try {
    const rows = query('SELECT * FROM users WHERE id=$1', [req.userId]);
    const row = rows.rows?.[0] || rows[0];
    const today = new Date().toISOString().slice(0, 10);
    const usageRows = query('SELECT count FROM usage_log WHERE user_id=$1 AND day=$2', [req.userId, today]);
    const used = usageRows.rows?.[0]?.count || 0;
    res.json({ 
      isPro: !!row.is_pro, 
      remaining: row.is_pro ? null : Math.max(0, 3 - used) 
    });
  } catch (e) {
    res.status(500).json({ error: 'internal' });
  }
});

const consumeLimiter = rateLimit({ windowMs: 60_000, max: 15 });

app.post('/api/generate/consume', authRequired, consumeLimiter, (req, res) => {
  try {
    const rows = query('SELECT * FROM users WHERE id=$1', [req.userId]);
    const row = rows.rows?.[0] || rows[0];
    if (row.is_pro) return res.json({ ok: true });
    
    const today = new Date().toISOString().slice(0, 10);
    const usageRows = query('SELECT count FROM usage_log WHERE user_id=$1 AND day=$2', [req.userId, today]);
    const used = usageRows.rows?.[0]?.count || 0;
    if (used >= 3) return res.status(402).json({ error: 'limit_reached' });
    
    query(
      `INSERT INTO usage_log (user_id, day, count) VALUES ($1,$2,1)
       ON CONFLICT (user_id, day) DO UPDATE SET count = usage_log.count + 1`,
      [req.userId, today]
    );
    query('UPDATE users SET podcasts_generated = podcasts_generated + 1 WHERE id=$1', [req.userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'internal' });
  }
});

// ── STRIPE ──────────────────────────────────────────────────────
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

app.post('/api/checkout', authRequired, express.json({ limit: '200kb' }), async (req, res) => {
  const { plan } = req.body || {};
  const priceIds = { 
    monthly: process.env.STRIPE_PRICE_MONTHLY, 
    yearly: process.env.STRIPE_PRICE_YEARLY, 
    lifetime: process.env.STRIPE_PRICE_LIFETIME 
  };
  if (!priceIds[plan]) return res.status(400).json({ error: 'invalid_plan' });
  
  try {
    const session = await stripe.checkout.sessions.create({
      mode: plan === 'lifetime' ? 'payment' : 'subscription',
      line_items: [{ price: priceIds[plan], quantity: 1 }],
      success_url: `${process.env.ALLOWED_ORIGIN || 'https://localhost'}/?upgraded=1`,
      cancel_url: `${process.env.ALLOWED_ORIGIN || 'https://localhost'}/?upgraded=0`,
      client_reference_id: req.userId,
    });
    res.json({ checkoutUrl: session.url });
  } catch (e) {
    res.status(500).json({ error: 'stripe_error' });
  }
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook signature invalid: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;
    const expiry = Date.now() + 31 * 24 * 3600 * 1000;
    try {
      query('UPDATE users SET is_pro=TRUE, plan=$1, pro_expiry=$2 WHERE id=$3', ['monthly', expiry, userId]);
    } catch (e) {
      console.error('Webhook error:', e);
    }
  }
  res.json({ received: true });
});

// ── TTS ────────────────────────────────────────────────────────────
const ttsLimiter = rateLimit({ windowMs: 60_000, max: 60 });

async function synthesizeEdge(text, voice, rate, pitch) {
  const esc = (t) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const ssml = `<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='nl-NL'><voice name='${voice}'><prosody rate='${rate}' pitch='${pitch}'>${esc(text)}</prosody></voice></speak>`;
  const wsUrl = `wss://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1?TrustedClientToken=${process.env.EDGE_TTS_TOKEN || '6A5AA1D4EAFF4E9FB37E23D68491D6F4'}&ConnectionId=${Date.now().toString(16)}`;
  
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl, { headers: { Origin: 'https://azure.microsoft.com' } });
    const chunks = [];
    const timeout = setTimeout(() => { 
      ws.close(); 
      reject(new Error('timeout')); 
    }, 12000);
    
    ws.on('open', () => {
      const ts = new Date().toISOString();
      ws.send(`X-Timestamp:${ts}\r\nContent-Type:application/json; charset=utf-8\r\nPath:speech.config\r\n\r\n{"context":{"synthesis":{"audio":{"outputFormat":"audio-24khz-48kbitrate-mono-mp3"}}}}`);
      ws.send(`X-RequestId:${ts}\r\nContent-Type:application/ssml+xml\r\nPath:ssml\r\n\r\n${ssml}`);
    });
    
    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        const sep = data.indexOf('Path:audio\r\n');
        if (sep !== -1) chunks.push(data.slice(sep + 12));
      } else if (data.toString().includes('Path:turn.end')) {
        clearTimeout(timeout);
        ws.close();
        resolve(Buffer.concat(chunks));
      }
    });
    
    ws.on('error', (e) => { 
      clearTimeout(timeout); 
      reject(e); 
    });
  });
}

app.post('/api/tts', authRequired, ttsLimiter, express.json({ limit: '200kb' }), async (req, res) => {
  const { text, voice, rate = '+0%', pitch = '+0Hz' } = req.body || {};
  if (!text || typeof text !== 'string' || text.length > 4000 || !voice) {
    return res.status(400).json({ error: 'invalid_input' });
  }
  try {
    const audio = await synthesizeEdge(text, voice, rate, pitch);
    res.set('Content-Type', 'audio/mpeg').send(audio);
  } catch (e) {
    console.error('TTS error:', e.message);
    res.status(502).json({ error: 'tts_failed', message: e.message });
  }
});

// ── START SERVER ──────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;

// Bind aan alle interfaces (belangrijk voor Render)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🎙️ CASTFABRIC V37 backend luistert op :${PORT}`);
  console.log(`📁 Database: SQLite (${dbPath})`);
  console.log(`✅ Klaar voor verzoeken!`);
});

// ── FOUTAFHANDELING ──────────────────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught exception:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled rejection:', err);
});
