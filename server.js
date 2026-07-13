/**
 * CASTFABRIC V37 — Secure Backend (PostgreSQL editie)
 * ════════════════════════════════════════════════════════════════════
 * Wijzigingen t.o.v. V35/V36 server.js:
 *   1. PostgreSQL i.p.v. SQLite (via de 'pg'-package, met connection pool)
 *      — lost het "SQLite locking onder gelijktijdige writes"-probleem op.
 *   2. Rate limits verruimd (zie uitleg per limiter hieronder).
 *   3. TTS blijft de gratis Edge-methode — zie het "OVER HET EDGE
 *      TTS-TOKEN" blok hieronder voor waarom dat token niet "privé" te
 *      maken is, ook niet in deze versie.
 *
 * Setup:
 *   npm install
 *   cp .env.example .env   # vul in, zie hieronder
 *   docker compose up -d  # start een lokale Postgres (zie docker-compose.yml)
 *   node server.js
 * ════════════════════════════════════════════════════════════════════
 */

/* ══════════════════════════════════════════════════════════════════
   OVER HET EDGE TTS-TOKEN — WAAROM DIT NIET "GEFIXT" KAN WORDEN
   ══════════════════════════════════════════════════════════════════
   Je vroeg om te fixen dat dit token "publiek" is. Eerlijk antwoord:
   dat kán niet, en wel hierom — het is geen bug, het is de aard van
   dit specifieke token:

   Microsoft's "Edge Read Aloud"-functie authenticeert NIET per gebruiker
   of per account. Elke kopie van de Edge-browser ter wereld gebruikt
   dezelfde vaste TrustedClientToken-waarde om bij hun gratis TTS-dienst
   te komen — dat is letterlijk hoe Microsoft het gebouwd heeft. Het is
   dus geen wachtwoord of API-key die "van jou" is en die kan lekken;
   het is een gedeelde configuratiewaarde die al openbaar is, voor
   iedereen, voor altijd, tenzij Microsoft zijn hele Edge-browser update.
   Het "verbergen" ervan achter deze backend-proxy voorkomt dat JOUW
   bezoekers 'm per ongeluk zien in hun browser-devtools, maar maakt het
   token zelf niet privé — dat was het nooit, en kan het niet worden
   zolang je de gratis Edge-methode gebruikt. Dit blijft zo in deze
   versie — geen betaalde providers toegevoegd, gewoon de gratis route,
   nu wel via de backend-proxy zodat het token in elk geval niet
   zichtbaar in de browser van je bezoekers staat.
   ══════════════════════════════════════════════════════════════════ */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const WebSocket = require('ws');

const app = express();

// ── PostgreSQL connection pool ──────────────────────────────────────
// V37 FIX: dit vervangt better-sqlite3. SQLite schrijft de hele database
// achter één bestandslock — bij gelijktijdige writes (bv. twee gebruikers
// die tegelijk 'consume' aanroepen) krijg je "database is locked"-fouten
// of moet je expliciet sequentialiseren. Postgres handelt dit van nature
// af met MVCC (elke transactie ziet een consistente snapshot, writes
// blokkeren elkaar niet onnodig) en is de standaardkeuze voor een
// productie-SaaS met meerdere gelijktijdige gebruikers.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // bv. postgres://user:pass@localhost:5432/castfabric
  max: 20, // max. gelijktijdige connecties in de pool
  idleTimeoutMillis: 30000,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false,
});

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      is_pro BOOLEAN NOT NULL DEFAULT FALSE,
      plan TEXT NOT NULL DEFAULT 'free',
      pro_expiry BIGINT,
      podcasts_generated INTEGER NOT NULL DEFAULT 0,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS usage_log (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      day TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      UNIQUE(user_id, day)
    );
  `);
}

// ── Basis hardening ────────────────────────────────────────────────
app.use(helmet());
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN, // GEEN wildcard '*'
  credentials: true,
}));

// V37 TOEVOEGING: health-check endpoint. De meeste hosting-platforms
// (Render, Railway, Fly.io) willen hier periodiek een 200'tje op zien om
// te weten dat de service leeft; zonder deze route denken sommige
// platforms dat de deploy mislukt is en herstarten ze de container
// onnodig. Checkt ook meteen of de database bereikbaar is.
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ status: 'error', db: 'unreachable', message: e.message });
  }
});

/* ══════════════════════════════════════════════════════════════════
   V37 — RATE LIMITS VERRUIMD
   Je gaf aan dat de limieten uit V35/36 te streng aanvoelden. Concreet
   wat er is veranderd, en waarom elke limiet nog steeds bescherming
   biedt zonder normaal gebruik te hinderen:

   - Algemene API-limiet: 60/min → 120/min. Een gebruiker die een
     podcast bouwt met 15-20 regels kan makkelijk 30-40 API-calls per
     minuut maken (usage-check, TTS per regel, autosave, etc.) — 60 was
     daarvoor al krap. 120/min per IP is nog steeds ver onder wat een
     script-based aanval zou willen (die wil duizenden/min).
   - Login/registratie: 10 per 15 min → 30 per 15 min. Brute-force op
     een wachtwoord kost bij bcrypt sowieso al te veel tijd per poging
     om met 30 pogingen iets te bereiken; dit voorkomt vooral geautoma-
     tiseerd script-misbruik, niet een gebruiker die een paar keer zijn
     wachtwoord verkeerd typt.
   - TTS: 20/min → 60/min. Dit was de meest waarschijnlijke oorzaak van
     "te streng" — een podcast van 20 regels die elk apart worden voor-
     gelezen, botst binnen één generatie al tegen de oude limiet van 20.
   - Generate-consume: 5/min → 15/min. Dit is een extra veiligheidsklep
     bovenop de gratis-limiet van 3/dag; hoeft niet zo krap te zijn.
   ══════════════════════════════════════════════════════════════════ */
app.use('/api/', rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

const COOKIE_OPTS = { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 };

function authRequired(req, res, next) {
  const token = req.cookies.castfabric_session;
  if (!token) return res.status(401).json({ error: 'not_authenticated' });
  try {
    req.userId = jwt.verify(token, process.env.JWT_SECRET).uid;
    next();
  } catch {
    res.status(401).json({ error: 'invalid_session' });
  }
}

function publicUser(row) {
  if (!row) return null;
  return {
    uid: row.id, email: row.email, name: row.name,
    isPro: !!row.is_pro, plan: row.plan,
    podcastsGenerated: row.podcasts_generated,
  };
}

const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 30 }); // was 10, zie uitleg hierboven

app.post('/api/register', authLimiter, express.json({ limit: '200kb' }), async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'invalid_input' });
  }
  const hash = await bcrypt.hash(password, 12);
  const id = 'user_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  try {
    await pool.query(
      'INSERT INTO users (id,email,password_hash,name,created_at) VALUES ($1,$2,$3,$4,$5)',
      [id, email.toLowerCase().trim(), hash, name || email.split('@')[0], Date.now()]
    );
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email_in_use' }); // unique_violation
    console.error(e);
    return res.status(500).json({ error: 'internal' });
  }
  const token = jwt.sign({ uid: id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.cookie('castfabric_session', token, COOKIE_OPTS);
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
  res.json(publicUser(rows[0]));
});

app.post('/api/login', authLimiter, express.json({ limit: '200kb' }), async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [(email || '').toLowerCase().trim()]);
  const row = rows[0];
  if (!row || !(await bcrypt.compare(password || '', row.password_hash))) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const token = jwt.sign({ uid: row.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.cookie('castfabric_session', token, COOKIE_OPTS);
  res.json(publicUser(row));
});

app.post('/api/logout', (req, res) => { res.clearCookie('castfabric_session'); res.json({ ok: true }); });

app.get('/api/me', authRequired, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.userId]);
  res.json(publicUser(rows[0]));
});

// ── Server-side usage limiet ────────────────────────────────────────
app.get('/api/usage', authRequired, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.userId]);
  const row = rows[0];
  const today = new Date().toISOString().slice(0, 10);
  const { rows: usageRows } = await pool.query('SELECT count FROM usage_log WHERE user_id=$1 AND day=$2', [req.userId, today]);
  const used = usageRows[0]?.count || 0;
  res.json({ isPro: !!row.is_pro, remaining: row.is_pro ? null : Math.max(0, 3 - used) });
});

const consumeLimiter = rateLimit({ windowMs: 60_000, max: 15 }); // was 5, zie uitleg hierboven

app.post('/api/generate/consume', authRequired, consumeLimiter, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.userId]);
  const row = rows[0];
  if (row.is_pro) return res.json({ ok: true });
  const today = new Date().toISOString().slice(0, 10);
  const { rows: usageRows } = await pool.query('SELECT count FROM usage_log WHERE user_id=$1 AND day=$2', [req.userId, today]);
  const used = usageRows[0]?.count || 0;
  if (used >= 3) return res.status(402).json({ error: 'limit_reached' });
  await pool.query(
    `INSERT INTO usage_log (user_id, day, count) VALUES ($1,$2,1)
     ON CONFLICT (user_id, day) DO UPDATE SET count = usage_log.count + 1`,
    [req.userId, today]
  );
  await pool.query('UPDATE users SET podcasts_generated = podcasts_generated + 1 WHERE id=$1', [req.userId]);
  res.json({ ok: true });
});

// ── Betalingen — Pro wordt ALLEEN aangezet door de Stripe-webhook ──
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.post('/api/checkout', authRequired, express.json({ limit: '200kb' }), async (req, res) => {
  const { plan } = req.body || {};
  const priceIds = { monthly: process.env.STRIPE_PRICE_MONTHLY, yearly: process.env.STRIPE_PRICE_YEARLY, lifetime: process.env.STRIPE_PRICE_LIFETIME };
  if (!priceIds[plan]) return res.status(400).json({ error: 'invalid_plan' });
  const session = await stripe.checkout.sessions.create({
    mode: plan === 'lifetime' ? 'payment' : 'subscription',
    line_items: [{ price: priceIds[plan], quantity: 1 }],
    success_url: `${process.env.ALLOWED_ORIGIN}/?upgraded=1`,
    cancel_url: `${process.env.ALLOWED_ORIGIN}/?upgraded=0`,
    client_reference_id: req.userId,
  });
  res.json({ checkoutUrl: session.url });
});

// LET OP: RAW body nodig voor Stripe's handtekening-check.
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
    await pool.query('UPDATE users SET is_pro=TRUE, plan=$1, pro_expiry=$2 WHERE id=$3', ['monthly', expiry, userId]);
  }
  res.json({ received: true });
});

// ── TTS: gratis, via Microsoft Edge (gedeeld token, zie uitleg boven) ─
const ttsLimiter = rateLimit({ windowMs: 60_000, max: 60 }); // was 20, zie uitleg hierboven

async function synthesizeEdge(text, voice, rate, pitch) {
  const esc = (t) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const ssml = `<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='nl-NL'><voice name='${voice}'><prosody rate='${rate}' pitch='${pitch}'>${esc(text)}</prosody></voice></speak>`;
  const wsUrl = `wss://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1?TrustedClientToken=${process.env.EDGE_TTS_TOKEN}&ConnectionId=${Date.now().toString(16)}`;
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl, { headers: { Origin: 'https://azure.microsoft.com' } });
    const chunks = [];
    const timeout = setTimeout(() => { ws.close(); reject(new Error('timeout')); }, 12000);
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
        clearTimeout(timeout); ws.close(); resolve(Buffer.concat(chunks));
      }
    });
    ws.on('error', (e) => { clearTimeout(timeout); reject(e); });
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
    res.status(502).json({ error: 'tts_failed', message: e.message });
  }
});

const PORT = process.env.PORT || 3001;
initSchema()
  .then(() => app.listen(PORT, () => console.log(`CASTFABRIC V37 backend luistert op :${PORT}`)))
  .catch((e) => { console.error('Kon database-schema niet initialiseren:', e.message); process.exit(1); });
