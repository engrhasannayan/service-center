import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';

const app = express();

/* ----------------------- Middleware ----------------------- */
app.use(express.json());
app.use(cookieParser());

// CORS: allow Angular dev server with credentials + common methods/headers
app.use(
  cors({
    origin: 'http://localhost:4200',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

/* -------------------- MongoDB connection ------------------ */
const uri = process.env.MONGODB_URI;
console.log('MONGODB_URI present?', !!uri);

mongoose
  .connect(uri)
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB connection error:', err.message));

/* ---------------------- Mongoose models ------------------- */
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, minlength: 3 },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);
const User = mongoose.model('User', userSchema);

// Refresh token store (opaque token with rotation & revocation)
const sessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    token: { type: String, unique: true, index: true }, // opaque random string
    expiresAt: { type: Date, index: true },
    createdAt: { type: Date, default: Date.now },
  },
  { versionKey: false }
);
const Session = mongoose.model('Session', sessionSchema);

/* ---------------------- Helpers --------------------------- */
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'dev_access_secret_change_me';
const ACCESS_TTL = process.env.ACCESS_TOKEN_TTL || '15m';
const REFRESH_TTL = process.env.REFRESH_TOKEN_TTL || '7d';

// Create JWT access token
function signAccessToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), name: user.fullName, email: user.email },
    ACCESS_SECRET,
    { expiresIn: ACCESS_TTL }
  );
}

// Create & store refresh session, return cookie payload
async function issueRefreshSession(userId) {
  const token = crypto.randomBytes(48).toString('hex'); // opaque random
  const expiresAt = new Date(Date.now() + parseDurationMs(REFRESH_TTL));
  await Session.create({ userId, token, expiresAt });
  return { token, expiresAt };
}

function parseDurationMs(s) {
  const n = parseInt(s, 10);
  if (s.endsWith('ms')) return n;
  if (s.endsWith('s')) return n * 1000;
  if (s.endsWith('m')) return n * 60 * 1000;
  if (s.endsWith('h')) return n * 60 * 60 * 1000;
  if (s.endsWith('d')) return n * 24 * 60 * 60 * 1000;
  return n; // fallback
}

// Cookie options — dev-friendly: lax; set secure:true in production (HTTPS)
const refreshCookieOpts = {
  httpOnly: true,
  secure: false,     // 👆 change to true in production behind HTTPS
  sameSite: 'lax',   // more forgiving in dev than 'strict'
  path: '/api',      // send cookie only to /api/* paths
};

/* ------------------------- Routes ------------------------- */

// Health
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || fullName.trim().length < 3) {
      return res.status(400).json({ message: 'Full name too short' });
    }
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email' });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ message: 'Password too short' });
    }

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ fullName, email, passwordHash });

    res.status(201).json({ id: user._id, fullName: user.fullName, email: user.email });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ message: 'Email already registered' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login -> returns access token JSON + sets refresh cookie
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email' });
    }
    if (!password) return res.status(400).json({ message: 'Password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = signAccessToken(user);
    const { token: refreshToken, expiresAt } = await issueRefreshSession(user._id);

    res
      .cookie('refreshToken', refreshToken, { ...refreshCookieOpts, expires: expiresAt })
      .json({
        accessToken,
        user: { id: user._id, fullName: user.fullName, email: user.email },
      });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Refresh -> rotate refresh token & return new access token
app.post('/api/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.cookies || {};
    if (!refreshToken) return res.status(401).json({ message: 'No refresh token' });

    const session = await Session.findOne({ token: refreshToken });
    if (!session || session.expiresAt < new Date()) {
      return res.status(401).json({ message: 'Invalid/expired refresh token' });
    }

    const user = await User.findById(session.userId);
    if (!user) return res.status(401).json({ message: 'User not found' });

    // rotate token: delete old, create new
    await Session.deleteOne({ _id: session._id });
    const { token: newRefresh, expiresAt } = await issueRefreshSession(user._id);
    const accessToken = signAccessToken(user);

    res
      .cookie('refreshToken', newRefresh, { ...refreshCookieOpts, expires: expiresAt })
      .json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout -> revoke session and clear cookie
app.post('/api/logout', async (req, res) => {
  try {
    const { refreshToken } = req.cookies || {};
    if (refreshToken) {
      await Session.deleteOne({ token: refreshToken });
    }
    // Express 5: do not pass "expires" here
    res.clearCookie('refreshToken', { ...refreshCookieOpts });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Example protected route
app.get('/api/me', authGuard, async (req, res) => {
  const user = await User.findById(req.userId).select('_id fullName email createdAt');
  if (!user) return res.status(404).json({ message: 'Not found' });
  res.json(user);
});

/* -------------------- Auth middleware --------------------- */
function authGuard(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.substring(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing access token' });

  try {
    const payload = jwt.verify(token, ACCESS_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid/expired token' });
  }
}

/* ---------------------- Start server ---------------------- */
const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`🚀 API running on http://localhost:${port}`);
});
