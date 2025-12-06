require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors');

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

app.use(express.json());


// --- Config from .env ---
// Prefer a backend port different from React dev server, e.g. 3001
const PORT = process.env.PORT || 3001;
const REGION = process.env.COGNITO_REGION;
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID = process.env.COGNITO_CLIENT_ID; // optional

if (!REGION || !USER_POOL_ID) {
  console.error('Missing COGNITO_REGION or COGNITO_USER_POOL_ID in .env');
  process.exit(1);
}

// --- JWKS client for Cognito ---
const client = jwksClient({
  jwksUri: `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}/.well-known/jwks.json`,
});

// Helper to get signing key for JWT verification
function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// --- Auth middleware: verifies JWT and attaches payload to req.user ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.substring('Bearer '.length)
    : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing Authorization: Bearer <token>' });
  }

  const issuer = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;

  jwt.verify(
    token,
    getKey,
    {
      algorithms: ['RS256'],
      issuer,
    },
    (err, decoded) => {
      if (err) {
        console.error('JWT verification error:', err);
        return res.status(401).json({ error: 'Invalid or expired token' });
      }

      // Optional: check client_id / aud matches expected client
      if (
        CLIENT_ID &&
        ((decoded.client_id && decoded.client_id !== CLIENT_ID) ||
          (decoded.aud && decoded.aud !== CLIENT_ID))
      ) {
        return res.status(401).json({ error: 'Token not issued for this client' });
      }

      req.user = decoded; // attach payload to request
      next();
    }
  );
}

// --- Routes ---
app.get('/', (req, res) => {
  return res.json({
    message: 'Hello world. Use /api/profile or /api/data endpoints.',
    payload: req.user,
  });
});


// 1) /api/profile -> shows the full JWT payload
app.get('/api/profile', authenticateToken, (req, res) => {
  return res.json({
    message: 'JWT payload',
    payload: req.user,
  });
});

// 2) /api/data -> behaviour based on role + custom:device_id
app.get('/api/data', authenticateToken, (req, res) => {
  const claims = req.user || {};
  const groups = claims['cognito:groups'] || [];
  const deviceId = claims['custom:device_id'];

  const isAdmin = Array.isArray(groups) && groups.includes('admin');
  const isUser = Array.isArray(groups) && groups.includes('user');

  let message;

  // TODO: connect with blob storage for fetching device data and do a filtering based on role + device_id
  if (isAdmin) {
    message = 'You are admin, you have access to all device_ids data.';
  } else if (isUser) {
    if (deviceId) {
      message = `You are user, you have access only to this device_id: ${deviceId}`;
    } else {
      message = 'You are user, but you have no device_id associated to your account yet.';
    }
  } else {
    message = 'You do not have a recognized role (admin or user).';
  }

  return res.json({
    message,
    roleGroups: groups,
    deviceId: deviceId || null,
  });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
