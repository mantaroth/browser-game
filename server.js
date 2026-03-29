const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const db = new Database(path.join(__dirname, 'players.db'));
const JWT_SECRET = process.env.JWT_SECRET || 'timberrealm-change-this-secret';
const PORT = process.env.PORT || 3000;

// ── Database setup ────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS players (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    last_login    INTEGER,
    data          TEXT    DEFAULT '{}'
  )
`);

// ── Middleware ────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname)));

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.player = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Session expired — please log in again' });
  }
}

// ── POST /api/register ────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required' });
  if (username.length < 3 || username.length > 20)
    return res.status(400).json({ error: 'Username must be 3–20 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username: letters, numbers and _ only' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare(
      'INSERT INTO players (username, password_hash, created_at) VALUES (?, ?, ?)'
    ).run(username, hash, Date.now());
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  } catch (e) {
    res.status(400).json({ error: 'That username is already taken' });
  }
});

// ── POST /api/login ───────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const player = db.prepare('SELECT * FROM players WHERE username = ?').get(username);
  if (!player || !bcrypt.compareSync(password, player.password_hash))
    return res.status(401).json({ error: 'Invalid username or password' });

  db.prepare('UPDATE players SET last_login = ? WHERE id = ?').run(Date.now(), player.id);
  const token = jwt.sign({ username: player.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: player.username, data: JSON.parse(player.data || '{}') });
});

// ── GET /api/player ───────────────────────────────────────────
app.get('/api/player', requireAuth, (req, res) => {
  const row = db.prepare('SELECT data FROM players WHERE username = ?').get(req.player.username);
  if (!row) return res.status(404).json({ error: 'Player not found' });
  res.json({ data: JSON.parse(row.data || '{}') });
});

// ── POST /api/save ────────────────────────────────────────────
app.post('/api/save', requireAuth, (req, res) => {
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'No data provided' });
  db.prepare('UPDATE players SET data = ? WHERE username = ?')
    .run(JSON.stringify(data), req.player.username);
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`TimberRealm running on port ${PORT}`));
