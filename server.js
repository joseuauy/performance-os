import 'dotenv/config';
import Anthropic from '@anthropic-ai/sdk';
import { createClient } from '@libsql/client';
import express from 'express';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ─── DATABASE ─────────────────────────────────────────────────────
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'performance.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = createClient({ url: `file:${dbPath}` });

await db.executeMultiple(`
  CREATE TABLE IF NOT EXISTS oauth_tokens (
    provider TEXT PRIMARY KEY,
    access_token TEXT,
    refresh_token TEXT,
    expires_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS checkins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    recovery INTEGER,
    hrv REAL,
    rhr INTEGER,
    sleep REAL,
    sleep_perf INTEGER,
    session_type TEXT,
    notes TEXT,
    strain REAL,
    steps INTEGER,
    ai_response TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    weight REAL,
    bf REAL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ─── ANTHROPIC ────────────────────────────────────────────────────
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const AI_MODEL = 'claude-sonnet-4-6';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const r = await db.execute({ sql: 'SELECT token FROM sessions WHERE token = ?', args: [token] });
  if (!r.rows.length) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.post('/api/auth/login', async (req, res) => {
  const { pin } = req.body;
  if (String(pin) !== String(process.env.APP_PIN || '832683')) {
    return res.status(401).json({ error: 'Wrong PIN' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  await db.execute({ sql: 'INSERT INTO sessions (token) VALUES (?)', args: [token] });
  res.json({ token });
});

// ─── TOKEN HELPERS ────────────────────────────────────────────────
async function getTokens(provider) {
  const r = await db.execute({ sql: 'SELECT * FROM oauth_tokens WHERE provider = ?', args: [provider] });
  return r.rows[0] || null;
}

async function saveTokens(provider, access_token, refresh_token, expires_in) {
  const expires_at = Date.now() + expires_in * 1000;
  await db.execute({
    sql: 'INSERT OR REPLACE INTO oauth_tokens (provider, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?)',
    args: [provider, access_token, refresh_token, expires_at],
  });
}

async function getValidWhoopToken() {
  const t = await getTokens('whoop');
  if (!t) return null;
  if (Date.now() < t.expires_at - 120_000) return t.access_token;
  try {
    const r = await fetch('https://api.prod.whoop.com/oauth/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: t.refresh_token,
        client_id: process.env.WHOOP_CLIENT_ID,
        client_secret: process.env.WHOOP_CLIENT_SECRET,
      }),
    });
    const d = await r.json();
    if (!d.access_token) { console.error('Whoop refresh failed:', d); return null; }
    await saveTokens('whoop', d.access_token, d.refresh_token || t.refresh_token, d.expires_in || 3600);
    return d.access_token;
  } catch (e) { console.error('Whoop refresh error:', e); return null; }
}

async function getValidStravaToken() {
  const t = await getTokens('strava');
  if (!t) return null;
  if (Date.now() < t.expires_at - 120_000) return t.access_token;
  try {
    const r = await fetch('https://www.strava.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.STRAVA_CLIENT_ID,
        client_secret: process.env.STRAVA_CLIENT_SECRET,
        refresh_token: t.refresh_token,
        grant_type: 'refresh_token',
      }),
    });
    const d = await r.json();
    if (!d.access_token) { console.error('Strava refresh failed:', d); return null; }
    const expiresIn = (d.expires_at || Math.floor(Date.now() / 1000) + 21600) - Math.floor(Date.now() / 1000);
    await saveTokens('strava', d.access_token, d.refresh_token || t.refresh_token, expiresIn);
    return d.access_token;
  } catch (e) { console.error('Strava refresh error:', e); return null; }
}

async function bootstrapStrava() {
  if (await getTokens('strava')) return;
  const refresh_token = process.env.STRAVA_REFRESH_TOKEN;
  if (!refresh_token) return;
  try {
    const r = await fetch('https://www.strava.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.STRAVA_CLIENT_ID,
        client_secret: process.env.STRAVA_CLIENT_SECRET,
        refresh_token,
        grant_type: 'refresh_token',
      }),
    });
    const d = await r.json();
    if (d.access_token) {
      const expiresIn = (d.expires_at || Math.floor(Date.now() / 1000) + 21600) - Math.floor(Date.now() / 1000);
      await saveTokens('strava', d.access_token, d.refresh_token || refresh_token, expiresIn);
      console.log('Strava bootstrapped from env refresh token');
    } else {
      console.error('Strava bootstrap failed:', d);
    }
  } catch (e) {
    console.error('Strava bootstrap error:', e);
  }
}

// ─── WHOOP OAUTH ──────────────────────────────────────────────────
app.get('/api/whoop/connect', requireAuth, (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.WHOOP_CLIENT_ID,
    redirect_uri: `${process.env.BASE_URL}/api/whoop/callback`,
    response_type: 'code',
    scope: 'read:recovery read:cycles read:sleep read:workout read:profile read:body_measurement offline',
    state: 'whoop',
  });
  res.redirect(`https://api.prod.whoop.com/oauth/oauth2/auth?${params}`);
});

app.get('/api/whoop/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect(`/?error=${error}`);
  try {
    const r = await fetch('https://api.prod.whoop.com/oauth/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.WHOOP_CLIENT_ID,
        client_secret: process.env.WHOOP_CLIENT_SECRET,
        redirect_uri: `${process.env.BASE_URL}/api/whoop/callback`,
      }),
    });
    const d = await r.json();
    if (!d.access_token) return res.redirect('/?error=whoop_token_failed');
    await saveTokens('whoop', d.access_token, d.refresh_token, d.expires_in || 3600);
    res.redirect('/?connected=whoop');
  } catch (e) {
    res.redirect('/?error=whoop_exception');
  }
});

// ─── WHOOP DATA ───────────────────────────────────────────────────
app.get('/api/whoop/today', requireAuth, async (req, res) => {
  const token = await getValidWhoopToken();
  if (!token) return res.json({ connected: false });

  async function whoopGet(p) {
    try {
      const r = await fetch(`https://api.prod.whoop.com/developer/v1${p}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) { console.error(`Whoop ${p} → ${r.status}`); return null; }
      return r.json();
    } catch (e) { console.error(`Whoop fetch error ${p}:`, e); return null; }
  }

  const [recovData, sleepData, cycleData] = await Promise.all([
    whoopGet('/recovery?limit=1'),
    whoopGet('/sleep?limit=1'),
    whoopGet('/cycle?limit=1'),
  ]);

  const recovery = recovData?.records?.[0];
  const sleep = sleepData?.records?.[0];
  const cycle = cycleData?.records?.[0];
  const recovDate = recovery?.created_at?.split('T')[0];

  res.json({
    connected: true,
    is_today: recovDate === new Date().toISOString().split('T')[0],
    data_date: recovDate || null,
    recovery: {
      score: recovery?.score?.recovery_score ?? null,
      hrv: recovery?.score?.hrv_rmssd_milli != null ? Math.round(recovery.score.hrv_rmssd_milli) : null,
      rhr: recovery?.score?.resting_heart_rate ?? null,
      skin_temp_c: recovery?.score?.skin_temp_celsius ?? null,
    },
    sleep: {
      duration_hours: sleep?.score?.total_in_bed_time_milli != null
        ? Math.round(sleep.score.total_in_bed_time_milli / 36000) / 100 : null,
      performance: sleep?.score?.sleep_performance_percentage ?? null,
      disturbances: sleep?.score?.disturbances ?? null,
    },
    cycle: {
      strain: cycle?.score?.strain != null ? Math.round(cycle.score.strain * 10) / 10 : null,
      avg_hr: cycle?.score?.average_heart_rate ?? null,
      kilojoules: cycle?.score?.kilojoule ?? null,
      steps: null,
    },
  });
});

// ─── STRAVA OAUTH ─────────────────────────────────────────────────
app.get('/api/strava/connect', requireAuth, (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.STRAVA_CLIENT_ID,
    redirect_uri: `${process.env.BASE_URL}/api/strava/callback`,
    response_type: 'code',
    scope: 'read,activity:read_all',
    approval_prompt: 'auto',
  });
  res.redirect(`https://www.strava.com/oauth/authorize?${params}`);
});

app.get('/api/strava/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect(`/?error=${error}`);
  try {
    const r = await fetch('https://www.strava.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.STRAVA_CLIENT_ID,
        client_secret: process.env.STRAVA_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
      }),
    });
    const d = await r.json();
    if (!d.access_token) return res.redirect('/?error=strava_token_failed');
    const expiresIn = (d.expires_at || Math.floor(Date.now() / 1000) + 21600) - Math.floor(Date.now() / 1000);
    await saveTokens('strava', d.access_token, d.refresh_token, expiresIn);
    res.redirect('/?connected=strava');
  } catch (e) {
    res.redirect('/?error=strava_exception');
  }
});

// ─── STRAVA DATA ──────────────────────────────────────────────────
app.get('/api/strava/recent', requireAuth, async (req, res) => {
  const token = await getValidStravaToken();
  if (!token) return res.json({ connected: false, activities: [] });

  try {
    const r = await fetch('https://www.strava.com/api/v3/athlete/activities?per_page=10', {
      headers: { Authorization: `Bearer ${token}` },
    });
    const acts = await r.json();
    if (!Array.isArray(acts)) return res.json({ connected: true, activities: [] });

    const rides = acts.filter(a => a.type === 'Ride' || a.type === 'VirtualRide').slice(0, 5);
    const detailed = await Promise.all(
      rides.map(async (act) => {
        try {
          const d = await fetch(`https://www.strava.com/api/v3/activities/${act.id}`, {
            headers: { Authorization: `Bearer ${token}` },
          }).then(r => r.json());
          return {
            id: act.id, name: act.name, date: act.start_date_local, type: act.type,
            distance_km: Math.round(act.distance / 100) / 10,
            duration_min: Math.round(act.moving_time / 60),
            elevation_m: Math.round(act.total_elevation_gain),
            avg_hr: act.average_heartrate ?? null, max_hr: act.max_heartrate ?? null,
            avg_watts: d.average_watts ?? null, max_watts: d.max_watts ?? null,
            weighted_avg_watts: d.weighted_average_watts ?? null,
            suffer_score: act.suffer_score ?? null, calories: d.calories ?? null,
          };
        } catch { return null; }
      })
    );
    res.json({ connected: true, activities: detailed.filter(Boolean) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── STATUS ───────────────────────────────────────────────────────
app.get('/api/status', async (req, res) => {
  res.json({ ok: true });
});

// ─── DASHBOARD AGGREGATE ──────────────────────────────────────────
app.get('/api/dashboard', requireAuth, async (req, res) => {
  const [histRes, latestCheckinRes, latestProgressRes, progressHistRes] = await Promise.all([
    db.execute('SELECT date, recovery, hrv, sleep, session_type FROM checkins ORDER BY created_at DESC LIMIT 30'),
    db.execute('SELECT * FROM checkins ORDER BY created_at DESC LIMIT 1'),
    db.execute('SELECT * FROM progress ORDER BY created_at DESC LIMIT 1'),
    db.execute('SELECT date, weight, bf FROM progress ORDER BY created_at ASC LIMIT 52'),
  ]);

  const history = histRes.rows;
  const latestCheckin = latestCheckinRes.rows[0] || null;
  const latestProgress = latestProgressRes.rows[0] || null;
  const progressHistory = progressHistRes.rows;

  let whoopData = null;
  const whoopToken = await getValidWhoopToken();
  if (whoopToken) {
    try {
      async function whoopGet(p) {
        const r = await fetch(`https://api.prod.whoop.com/developer/v1${p}`, {
          headers: { Authorization: `Bearer ${whoopToken}` },
        });
        return r.ok ? r.json() : null;
      }
      const [recovData, sleepData, cycleData] = await Promise.all([
        whoopGet('/recovery?limit=1'),
        whoopGet('/sleep?limit=1'),
        whoopGet('/cycle?limit=1'),
      ]);
      const recovery = recovData?.records?.[0];
      const sleep = sleepData?.records?.[0];
      const cycle = cycleData?.records?.[0];
      const recovDate = recovery?.created_at?.split('T')[0];
      whoopData = {
        is_today: recovDate === new Date().toISOString().split('T')[0],
        data_date: recovDate || null,
        recovery: {
          score: recovery?.score?.recovery_score ?? null,
          hrv: recovery?.score?.hrv_rmssd_milli != null ? Math.round(recovery.score.hrv_rmssd_milli) : null,
          rhr: recovery?.score?.resting_heart_rate ?? null,
        },
        sleep: {
          duration_hours: sleep?.score?.total_in_bed_time_milli != null
            ? Math.round(sleep.score.total_in_bed_time_milli / 36000) / 100 : null,
          performance: sleep?.score?.sleep_performance_percentage ?? null,
        },
        cycle: {
          strain: cycle?.score?.strain != null ? Math.round(cycle.score.strain * 10) / 10 : null,
        },
      };
    } catch {}
  }

  let lastRide = null;
  const stravaToken = await getValidStravaToken();
  if (stravaToken) {
    try {
      const r = await fetch('https://www.strava.com/api/v3/athlete/activities?per_page=5', {
        headers: { Authorization: `Bearer ${stravaToken}` },
      });
      const acts = await r.json();
      const ride = Array.isArray(acts) ? acts.find(a => a.type === 'Ride' || a.type === 'VirtualRide') : null;
      if (ride) {
        const d = await fetch(`https://www.strava.com/api/v3/activities/${ride.id}`, {
          headers: { Authorization: `Bearer ${stravaToken}` },
        }).then(r => r.json());
        lastRide = {
          name: ride.name, date: ride.start_date_local, type: ride.type,
          distance_km: Math.round(ride.distance / 100) / 10,
          duration_min: Math.round(ride.moving_time / 60),
          elevation_m: Math.round(ride.total_elevation_gain),
          avg_hr: ride.average_heartrate ?? null,
          avg_watts: d.average_watts ?? null,
          weighted_avg_watts: d.weighted_average_watts ?? null,
          max_watts: d.max_watts ?? null,
        };
      }
    } catch {}
  }

  const whoopConnected = !!(await getTokens('whoop'));
  const stravaConnected = !!(await getTokens('strava'));

  res.json({ history, latestCheckin, latestProgress, progressHistory, whoopData, lastRide, whoop_connected: whoopConnected, strava_connected: stravaConnected });
});

// ─── POWER CURVE ──────────────────────────────────────────────────
app.get('/api/strava/power-curve', requireAuth, async (req, res) => {
  const token = await getValidStravaToken();
  if (!token) return res.json({ connected: false });

  try {
    const r = await fetch('https://www.strava.com/api/v3/athlete/activities?per_page=20', {
      headers: { Authorization: `Bearer ${token}` },
    });
    const acts = await r.json();
    const rides = Array.isArray(acts)
      ? acts.filter(a => (a.type === 'Ride' || a.type === 'VirtualRide') && a.device_watts).slice(0, 5)
      : [];

    if (!rides.length) return res.json({ connected: true, curve: null, message: 'No power-meter rides found' });

    const durations = [5, 10, 30, 60, 300, 600, 1200, 3600];
    const bestPower = {};
    durations.forEach(d => { bestPower[d] = 0; });

    for (const ride of rides) {
      try {
        const sr = await fetch(
          `https://www.strava.com/api/v3/activities/${ride.id}/streams?keys=watts&resolution=high`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        const streams = await sr.json();
        const wattsStream = Array.isArray(streams) ? streams.find(s => s.type === 'watts') : null;
        if (!wattsStream?.data?.length) continue;
        const watts = wattsStream.data;
        for (const dur of durations) {
          if (watts.length < dur) continue;
          let windowSum = 0;
          for (let i = 0; i < dur; i++) windowSum += (watts[i] || 0);
          let maxAvg = windowSum / dur;
          for (let i = dur; i < watts.length; i++) {
            windowSum += (watts[i] || 0) - (watts[i - dur] || 0);
            const avg = windowSum / dur;
            if (avg > maxAvg) maxAvg = avg;
          }
          if (maxAvg > bestPower[dur]) bestPower[dur] = maxAvg;
        }
      } catch {}
    }

    res.json({
      connected: true,
      curve: durations.map(d => ({ duration: d, power: bestPower[d] > 0 ? Math.round(bestPower[d]) : null })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── CHECK-IN ─────────────────────────────────────────────────────
const SESSION_NAMES = {
  legs: 'Legs — Mon hypertrophy (quads, hamstrings, glutes)',
  push: 'Push — Tue chest, shoulders, triceps',
  arms: 'Arms/Pull-ups — Wed biceps, pull-ups, forearms',
  pull: 'Pull — Thu rows, pulldowns, rear delts',
  ftp: 'FTP Test or Indoor Cycling — Fri',
  cycling: 'Outdoor Cycling — Sat',
  rest: 'Rest Day — Sun',
};

async function buildCoachingContext() {
  const histRes = await db.execute('SELECT * FROM checkins ORDER BY created_at DESC LIMIT 30');
  const progRes = await db.execute('SELECT * FROM progress ORDER BY created_at DESC LIMIT 8');
  const history = histRes.rows;
  const progress = progRes.rows;

  let histCtx = 'No previous check-ins yet.';
  if (history.length) {
    const avg = Math.round(history.reduce((s, h) => s + h.recovery, 0) / history.length);
    let greenStreak = 0;
    for (const h of history) { if (h.recovery >= 67) greenStreak++; else break; }
    histCtx = `TRAINING HISTORY (last ${history.length} days, newest first):\n`
      + history.slice(0, 14).map(h =>
          `  ${h.date}: Recovery ${h.recovery}%${h.hrv ? ', HRV ' + h.hrv + 'ms' : ''}${h.rhr ? ', RHR ' + h.rhr : ''}${h.sleep ? ', Sleep ' + h.sleep + 'h' : ''}${h.sleep_perf ? '/' + h.sleep_perf + '%' : ''}, Session: ${h.session_type}${h.notes ? ' — "' + h.notes + '"' : ''}`
        ).join('\n')
      + `\n  30-day avg recovery: ${avg}%  |  Current green streak: ${greenStreak} days`;
  }

  let progCtx = '';
  if (progress.length) {
    const latest = progress[0];
    const first = progress[progress.length - 1];
    progCtx = `\nBODY COMPOSITION TREND (${progress.length} entries):\n`
      + `  Latest: ${latest.weight || '?'}lbs, ${latest.bf || '?'}% BF (${latest.date})\n`
      + (progress.length > 1 ? `  Start: ${first.weight || '?'}lbs, ${first.bf || '?'}% BF (${first.date})` : '');
  }

  return { histCtx, progCtx };
}

app.post('/api/checkin', requireAuth, async (req, res) => {
  const { recovery, hrv, rhr, sleep, sleep_perf, session_type, notes, strain } = req.body;
  if (!recovery) return res.status(400).json({ error: 'Recovery % required' });

  const { histCtx, progCtx } = await buildCoachingContext();
  const tier = recovery >= 67 ? 'GREEN' : recovery >= 34 ? 'YELLOW' : 'RED';

  const prompt = `You are José's personal performance coach with full memory of his training history.\n\nATHLETE PROFILE:\n- José, 5'10", ~175lbs, ~15% body fat. Goal: reach 11-12% BF.\n- Busy dad (4 kids). Trains at 5:30am. Coach Francisco Jara's hypertrophy program: 3 exercises/day, train to failure.\n- Weekly split: Mon Legs, Tue Push, Wed Arms/Pull-ups, Thu Pull, Fri rest or FTP, Sat outdoor cycling, Sun rest.\n- Wahoo KICKR + Roovy for indoor. Biggest challenges: late-night sugar cravings, Netflix-induced sleep debt (<7hrs), vacation setbacks.\n- Eats eggs, chicken, red meat, Greek yogurt. Protein target: 175g/day.\n- Historical pattern: when sleep < 7h or HRV drops below 25ms, performance suffers next session.\n\n${histCtx}\n${progCtx}\n\nTODAY (${new Date().toISOString().split('T')[0]}):\n- Recovery: ${recovery}% → ${tier}\n- HRV: ${hrv || 'not provided'}ms\n- Resting HR: ${rhr || 'not provided'}bpm\n- Sleep: ${sleep || 'not provided'}h\n- Sleep performance: ${sleep_perf || 'not provided'}%\n- Strain (yesterday): ${strain || 'not provided'}\n- Planned session: ${SESSION_NAMES[session_type] || session_type}\n- Notes: "${notes || 'none'}"\n\nWrite a sharp, personal coaching note (130–160 words). Three tight paragraphs:\n1. What today's numbers mean — compare to his recent trend if you see a pattern worth calling out\n2. How to execute today's session given this recovery (be specific: RPE, rest periods, which exercises to protect or push)\n3. One concrete nutrition or sleep action for tonight that targets his biggest weakness\n\nTone: direct, warm, like a coach who knows him well. Use "José" once. No headers, no bullets. Reference specific numbers.`;

  try {
    const msg = await anthropic.messages.create({
      model: AI_MODEL, max_tokens: 512,
      messages: [{ role: 'user', content: prompt }],
    });
    const aiResponse = msg.content[0].text;
    const date = new Date().toISOString().split('T')[0];
    await db.execute({
      sql: 'INSERT INTO checkins (date, recovery, hrv, rhr, sleep, sleep_perf, session_type, notes, strain, ai_response) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [date, recovery, hrv || null, rhr || null, sleep || null, sleep_perf || null, session_type, notes || null, strain || null, aiResponse],
    });
    res.json({ ok: true, ai_response: aiResponse });
  } catch (e) {
    console.error('Claude error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── WEEKLY REPORT ────────────────────────────────────────────────
app.post('/api/weekly', requireAuth, async (req, res) => {
  const r = await db.execute('SELECT * FROM checkins ORDER BY created_at DESC LIMIT 7');
  const history = r.rows;
  if (!history.length) return res.status(400).json({ error: 'No check-in data yet' });

  const avg = Math.round(history.reduce((s, h) => s + h.recovery, 0) / history.length);
  const greenDays = history.filter(h => h.recovery >= 67).length;
  const dataStr = history.map(h =>
    `${h.date}: Recovery ${h.recovery}%${h.hrv ? ', HRV ' + h.hrv + 'ms' : ''}${h.rhr ? ', RHR ' + h.rhr : ''}${h.sleep ? ', Sleep ' + h.sleep + 'h' : ''}, Session: ${h.session_type}${h.notes ? ' — "' + h.notes + '"' : ''}`
  ).join('\n');

  const { progCtx } = await buildCoachingContext();

  try {
    const msg = await anthropic.messages.create({
      model: AI_MODEL, max_tokens: 600,
      messages: [{ role: 'user', content: `Weekly coaching report for José (5'10", ~175lbs, goal 11-12% BF, busy dad training at 5:30am).\n\nWEEK DATA:\n${dataStr}\nAvg recovery: ${avg}%  |  Green days: ${greenDays}/7\n${progCtx}\n\nWrite a 200-word report (flowing paragraphs, no headers): recovery trend + what it means, training quality, one thing he did well, one specific thing to fix, next week's priority. Be specific with numbers.` }],
    });
    res.json({ ok: true, report: msg.content[0].text });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── CYCLING PLAN ─────────────────────────────────────────────────
app.post('/api/cycling', requireAuth, async (req, res) => {
  const { dist, dur, hr, elev, feel, ftp } = req.body;

  let stravaCtx = '';
  const stravaToken = await getValidStravaToken();
  if (stravaToken) {
    try {
      const r = await fetch('https://www.strava.com/api/v3/athlete/activities?per_page=3', {
        headers: { Authorization: `Bearer ${stravaToken}` },
      });
      const acts = await r.json();
      const rides = Array.isArray(acts) ? acts.filter(a => a.type === 'Ride' || a.type === 'VirtualRide') : [];
      if (rides.length) {
        stravaCtx = `Recent Strava rides:\n` + rides.map(r =>
          `  ${r.start_date_local?.split('T')[0]}: ${Math.round(r.distance/1000)}km, ${Math.round(r.moving_time/60)}min, ${r.average_heartrate || '?'}bpm avg HR`
        ).join('\n');
      }
    } catch {}
  }

  const latestRes = await db.execute('SELECT recovery FROM checkins ORDER BY created_at DESC LIMIT 1');
  const latest = latestRes.rows[0] || null;

  try {
    const msg = await anthropic.messages.create({
      model: AI_MODEL, max_tokens: 500,
      messages: [{ role: 'user', content: `Cycling coach for José. Recreational cyclist improving Saturday outdoor performance. Wahoo KICKR + Roovy. ${ftp ? 'FTP: ' + ftp + 'w.' : 'No FTP tested yet.'} ${latest ? 'Latest recovery: ' + latest.recovery + '%.' : ''}\n\n${stravaCtx}\n\nSaturday ride just completed: ${dist || '?'}km, ${dur || '?'}min, avg HR ${hr || '?'}bpm, ${elev || '?'}m elevation, felt: ${feel}.\n\nDesign 2 indoor sessions (Wednesday easy + Friday structured). Each: duration, type, specific intervals with HR zone or watt target, session goal. Practical. 180 words max.` }],
    });
    res.json({ ok: true, plan: msg.content[0].text });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── NUTRITION ────────────────────────────────────────────────────
const NUTRITION_TARGETS = {
  training: { cals: 2400, prot: 175, carbs: 240, fat: 65 },
  rest: { cals: 2000, prot: 175, carbs: 170, fat: 65 },
  cycling: { cals: 2700, prot: 175, carbs: 310, fat: 65 },
};

app.post('/api/nutrition', requireAuth, async (req, res) => {
  const { day_type, available } = req.body;
  const t = NUTRITION_TARGETS[day_type] || NUTRITION_TARGETS.training;
  const latestRes = await db.execute('SELECT recovery FROM checkins ORDER BY created_at DESC LIMIT 1');
  const latest = latestRes.rows[0] || null;
  const availLabel = { home: 'cooking at home', restaurant: 'eating out', mixed: 'mix of home and eating out' }[available] || available;

  try {
    const msg = await anthropic.messages.create({
      model: AI_MODEL, max_tokens: 600,
      system: 'Return only a valid JSON array. No markdown fences, no explanation, no extra text.',
      messages: [{ role: 'user', content: `Meal plan for José. ${t.cals} cal ${day_type} day. Target: 175g protein. ${availLabel}. Foods he eats: eggs, chicken, red meat (steak/ground beef), Greek yogurt, rice, oats, fruit. ${latest ? 'Recovery today: ' + latest.recovery + '%.' : ''} Late-night cravings are his biggest risk — the evening snack must be planned.\n\nReturn JSON array of 5 meals: [{time: "7:00 AM", name: "...", foods: "...", protein: 40}]\nMeals must total ~175g protein. Be specific with portions.` }],
    });
    const raw = msg.content[0].text.replace(/```json|```/g, '').trim();
    let meals;
    try { meals = JSON.parse(raw); } catch { meals = []; }
    res.json({ ok: true, meals, targets: t });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── HISTORY & PROGRESS ───────────────────────────────────────────
app.get('/api/history', requireAuth, async (req, res) => {
  const r = await db.execute('SELECT * FROM checkins ORDER BY created_at DESC LIMIT 60');
  res.json(r.rows);
});

app.post('/api/progress', requireAuth, async (req, res) => {
  const { weight, bf } = req.body;
  if (!weight && !bf) return res.status(400).json({ error: 'Need weight or BF' });
  const date = new Date().toISOString().split('T')[0];
  await db.execute({ sql: 'INSERT INTO progress (date, weight, bf) VALUES (?, ?, ?)', args: [date, weight || null, bf || null] });
  res.json({ ok: true });
});

app.get('/api/progress', requireAuth, async (req, res) => {
  const r = await db.execute('SELECT * FROM progress ORDER BY created_at ASC LIMIT 52');
  res.json(r.rows);
});

// ─── START ────────────────────────────────────────────────────────
await bootstrapStrava();
app.listen(PORT, () => console.log(`Performance OS v2 running on port ${PORT}`));
