'use strict';

const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

require('dotenv').config();

const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const FabricCAServices = require('fabric-ca-client');
const { User, Utils } = require('fabric-common');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const BUILD_ID = 'APPJS_AUTH_SQLITE_JWT_CA_2026-03-02_V1';

const app = express();
app.use(bodyParser.json());

/**
 * CONFIG
 */
const PORT = Number(process.env.PORT || 3000);

const channelName = process.env.CHANNEL || 'mychannel';
const chaincodeName = process.env.CHAINCODE || 'document-contract';
const peerName = process.env.PEER_NAME || 'peer0.org1.example.com';
const mspId = process.env.MSP_ID || 'Org1MSP';

// files
const ccpPath = process.env.CCP_PATH || path.join(__dirname, 'fabric', 'connection-org1.json');
const tlsCaPath = process.env.PEER_TLS_CA_PATH || path.join(__dirname, 'fabric', 'tls', 'ca.crt');

// Fabric identities (server-side “wallet”)
const usersRoot = process.env.USERS_ROOT || path.join(__dirname, 'fabric', 'users');

// CA admin creds (test-network default)
const caAdminId = process.env.CA_ADMIN || 'admin';
const caAdminSecret = process.env.CA_ADMIN_PW || 'adminpw';

// JWT
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_change_this';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

// Platform bootstrap admin (web admin)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

// SQLite
const USERS_DB_PATH =
  process.env.USERS_DB_PATH || path.join(__dirname, 'data', 'users.sqlite');

/**
 * Small helpers
 */
function bytesToUtf8(result) {
  return Buffer.from(result).toString('utf8');
}
function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}
function readFileStrict(p, label) {
  if (!fs.existsSync(p)) throw new Error(`Missing file: ${label} (${p})`);
  return fs.readFileSync(p);
}
function loadSignerFromKeyPath(keyPath) {
  const privateKeyPem = readFileStrict(keyPath, 'user key');
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  return signers.newPrivateKeySigner(privateKey);
}

function userPaths(userId) {
  const base = path.join(usersRoot, userId);
  return {
    base,
    certPath: path.join(base, 'cert.pem'),
    keyPath: path.join(base, 'key.pem'),
  };
}

function loadIdentityForUser(userId) {
  const { certPath, keyPath } = userPaths(userId);

  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw new Error(
      `Fabric identity missing for user "${userId}". Expected cert/key at: ${certPath}, ${keyPath}`
    );
  }

  return {
    userId,
    credentials: readFileStrict(certPath, 'user cert'),
    signer: loadSignerFromKeyPath(keyPath),
  };
}

function newGatewayForUser(userId) {
  const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));
  const peer = ccp.peers?.[peerName];
  if (!peer?.url) throw new Error(`Peer config missing for ${peerName}`);

  const tlsRootCert = readFileStrict(tlsCaPath, 'peer tls ca.crt');
  const credentials = grpc.credentials.createSsl(tlsRootCert);

  const endpoint = peer.url.replace(/^grpcs:\/\//, '');
  const sslTarget =
    peer.grpcOptions?.['ssl-target-name-override'] ||
    peer.grpcOptions?.hostnameOverride ||
    peerName;

  const client = new grpc.Client(endpoint, credentials, {
    'grpc.ssl_target_name_override': sslTarget,
    'grpc.default_authority': sslTarget,
  });

  const id = loadIdentityForUser(userId);

  return connect({
    client,
    identity: { mspId, credentials: id.credentials },
    signer: id.signer,
  });
}

function stringifyAny(x) {
  if (x === undefined || x === null) return '';
  if (typeof x === 'string') return x;
  try {
    return JSON.stringify(x);
  } catch {
    return String(x);
  }
}


function extractJsonAfterMarker(hay, marker) {
  const idx = hay.indexOf(marker);
  if (idx === -1) return null;

  const tail = hay.slice(idx + marker.length);
  const start = tail.indexOf('{');
  if (start === -1) return null;

  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = start; i < tail.length; i++) {
    const ch = tail[i];

    if (escape) {
      escape = false;
      continue;
    }
    if (ch === '\\') {
      escape = true;
      continue;
    }

    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;

    if (ch === '{') depth++;
    if (ch === '}') depth--;

    if (depth === 0) return tail.slice(start, i + 1);
  }
  return null;
}

function parseDuplicateError(err) {
  const marker = 'DUPLICATE_HASH:';
  const hay = [stringifyAny(err?.details), stringifyAny(err?.message), stringifyAny(err)]
    .filter(Boolean)
    .join(' | ');

  if (!hay.includes(marker)) return null;

  const jsonText = extractJsonAfterMarker(hay, marker);
  if (!jsonText) {
    return {
      code: 'DUPLICATE_HASH',
      message: 'Duplicate hash',
      raw: 'Marker found but JSON not extracted',
    };
  }

  try {
    return JSON.parse(jsonText);
  } catch {
    try {
      return JSON.parse(jsonText.replace(/\\"/g, '"'));
    } catch {
      return { code: 'DUPLICATE_HASH', message: 'Duplicate hash', raw: jsonText };
    }
  }
}

function parseChaincodeJson(buf) {
  const raw = bytesToUtf8(buf);
  try {
    return JSON.parse(raw);
  } catch {
    return { warning: 'Chaincode response is not valid JSON', raw };
  }
}

async function evalTx(contract, fn, ...args) {
  const r = await contract.evaluateTransaction(fn, ...args.map((a) => String(a)));
  return parseChaincodeJson(r);
}

async function submitTx(contract, fn, ...args) {
  const r = await contract.submitTransaction(fn, ...args.map((a) => String(a)));
  return parseChaincodeJson(r);
}

/**
 * -------- SQLite users (web accounts) --------
 */
function initDb() {
  ensureDir(path.dirname(USERS_DB_PATH));
  const db = new Database(USERS_DB_PATH);

  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','user')),
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
      created_at TEXT NOT NULL
    );
  `);

  const cols = db.prepare(`PRAGMA table_info(users)`).all();
  const hasStatus = cols.some(c => c.name === 'status');
  if (!hasStatus) {
    db.exec(`
      ALTER TABLE users
      ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'
      CHECK (status IN ('ACTIVE','DISABLED'));
    `);
  }

  return db;
}

const db = initDb();

function getUserFromDb(userId) {
  return db
    .prepare('SELECT id, password_hash, role, status, created_at FROM users WHERE id = ?')
    .get(userId);
}

function createUserInDb(userId, passwordPlain, role) {
  const now = new Date().toISOString();
  const password_hash = bcrypt.hashSync(passwordPlain, 12);

  db.prepare(
    'INSERT INTO users (id, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, password_hash, role, 'ACTIVE', now);

  return { id: userId, role, status: 'ACTIVE', created_at: now };
}

function setUserStatusInDb(userId, status) {
  const s = String(status || '').toUpperCase();
  if (!['ACTIVE', 'DISABLED'].includes(s)) {
    throw new Error('Invalid user status');
  }

  const result = db
    .prepare('UPDATE users SET status = ? WHERE id = ?')
    .run(s, userId);

  return result.changes > 0;
}

function resetUserPasswordInDb(userId, passwordPlain) {
  const password_hash = bcrypt.hashSync(passwordPlain, 12);
  const result = db
    .prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .run(password_hash, userId);

  return result.changes > 0;
}

function ensureBootstrapAdmin() {
  const existing = getUserFromDb(ADMIN_USERNAME);
  if (existing) return;

  createUserInDb(ADMIN_USERNAME, ADMIN_PASSWORD, 'admin');
  console.log(`[BOOTSTRAP] Admin user created in SQLite: ${ADMIN_USERNAME}`);
}

/**
 * -------- JWT auth --------
 */
function issueJwt(userId, role) {
  return jwt.sign({ sub: userId, role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function requireJwt(req, res, next) {
  const h = req.header('authorization') || '';
  if (!h.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({ error: 'Missing Bearer token' });
  }

  const token = h.split(' ', 2)[1]?.trim();
  if (!token) return res.status(401).json({ error: 'Missing Bearer token' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const sub = String(payload?.sub || '').trim();
    if (!sub) return res.status(401).json({ error: 'Invalid token: sub missing' });

    req.user = payload;
    req.userId = sub;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token', details: String(e?.message || e) });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin required' });
  next();
}

/**
 * -------- CA (register/enroll) --------
 */
function getCaInfoFromCcp() {
  const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));
  const org =
    ccp.organizations?.Org1 || ccp.organizations?.[Object.keys(ccp.organizations || {})[0]];
  const caKey = org?.certificateAuthorities?.[0];
  if (!caKey) throw new Error('CA not found in connection profile organizations');

  const ca = ccp.certificateAuthorities?.[caKey];
  if (!ca?.url) throw new Error('CA url missing from connection profile');

  const caPemArr = ca.tlsCACerts?.pem;
  const caPem = Array.isArray(caPemArr) ? caPemArr.join('\n') : String(caPemArr || '');
  return { caUrl: ca.url, caName: ca.caName || caKey, caPem };
}

let caAdminUserCache = null;

async function getCaAdminUser(caService) {
  if (caAdminUserCache) return caAdminUserCache;

  const enrollment = await caService.enroll({
    enrollmentID: caAdminId,
    enrollmentSecret: caAdminSecret,
  });

  const cryptoSuite = Utils.newCryptoSuite();
  const adminUser = new User(caAdminId);
  adminUser.setCryptoSuite(cryptoSuite);

  await adminUser.setEnrollment(enrollment.key, enrollment.certificate, mspId);

  caAdminUserCache = adminUser;
  return adminUser;
}

async function registerAndEnrollUser(userId, enrollmentSecret) {
  if (!userId || typeof userId !== 'string') throw new Error('userId required');
  if (!enrollmentSecret || typeof enrollmentSecret !== 'string')
    throw new Error('enrollmentSecret required');

  const { caUrl, caName, caPem } = getCaInfoFromCcp();

  const tlsOptions = caPem ? { trustedRoots: [caPem], verify: false } : { verify: false };
  const caService = new FabricCAServices(caUrl, tlsOptions, caName);

  const adminUser = await getCaAdminUser(caService);

  try {
    await caService.register(
      {
        enrollmentID: userId,
        enrollmentSecret: enrollmentSecret, 
        affiliation: 'org1.department1',
        role: 'client',
        maxEnrollments: -1,
      },
      adminUser
    );
  } catch (e) {
    const msg = String(e?.message || e).toLowerCase();
    const exists = msg.includes('already') || msg.includes('exists');
    if (!exists) throw e;
    
  }

  const enrollment = await caService.enroll({
    enrollmentID: userId,
    enrollmentSecret: enrollmentSecret,
  });

  const p = userPaths(userId);
  ensureDir(p.base);
  fs.writeFileSync(p.certPath, enrollment.certificate);
  fs.writeFileSync(p.keyPath, enrollment.key.toBytes());

  return { enrolled: true, userId };
}


async function ensureBootstrapAdminFabricIdentity() {
  const p = userPaths(ADMIN_USERNAME);
  const has = fs.existsSync(p.certPath) && fs.existsSync(p.keyPath);
  if (has) return { alreadyPresent: true, userId: ADMIN_USERNAME };

  // Provision admin identity using ADMIN_PASSWORD as enrollment secret
  const out = await registerAndEnrollUser(ADMIN_USERNAME, ADMIN_PASSWORD);
  console.log(`Fabric identity created for admin: ${ADMIN_USERNAME}`);
  return out;
}

/**
 * ---------------- routes ----------------
 */
app.get('/health', (_req, res) =>
  res.json({
    ok: true,
    build: BUILD_ID,
    channelName,
    chaincodeName,
    mspId,
    peerName,
  })
);


app.post('/auth/login', async (req, res) => {
  try {
    const { userId, password } = req.body || {};
    const uid = String(userId || '').trim();
    const pw = String(password || '');

    if (!uid || !pw) {
      return res.status(400).json({ error: 'userId and password required' });
    }

    const u = getUserFromDb(uid);
    if (!u) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (String(u.status || 'ACTIVE').toUpperCase() !== 'ACTIVE') {
      return res.status(403).json({ error: 'User is disabled' });
    }

    const ok = bcrypt.compareSync(pw, u.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const up = userPaths(uid);
    const hasIdentity = fs.existsSync(up.certPath) && fs.existsSync(up.keyPath);
    if (!hasIdentity) {
      return res.status(403).json({
        error: 'Fabric identity missing for this user',
        details: 'Ask admin to provision this user (CA register+enroll) before using the platform.',
      });
    }

    const token = issueJwt(uid, u.role);
    return res.json({
      ok: true,
      token,
      user: {
        id: u.id,
        role: u.role,
        status: u.status || 'ACTIVE',
      },
    });
  } catch (e) {
    return res.status(500).json({ error: 'Login failed', details: String(e?.message || e) });
  }
});


app.post('/admin/users', requireJwt, requireAdmin, async (req, res) => {
  try {
    const { userId, password, role } = req.body || {};
    const uid = String(userId || '').trim();
    const pw = String(password || '');

    const r = (String(role || 'user').toLowerCase() === 'admin') ? 'admin' : 'user';

    if (!uid || !pw) return res.status(400).json({ error: 'userId and password required' });
    if (uid.length < 2) return res.status(400).json({ error: 'userId too short' });
    if (pw.length < 4) return res.status(400).json({ error: 'password too short' });

    const existing = getUserFromDb(uid);
    if (existing) return res.status(409).json({ error: 'User already exists (web DB)' });

    const webUser = createUserInDb(uid, pw, r);

    const caOut = await registerAndEnrollUser(uid, pw);

    return res.json({
      ok: true,
      user: { id: webUser.id, role: webUser.role, created_at: webUser.created_at },
      fabric: caOut,
    });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to create user', details: String(e?.message || e) });
  }
});

app.get('/admin/users', requireJwt, requireAdmin, (req, res) => {
  try {
    const rows = db
      .prepare('SELECT id, role, status, created_at FROM users ORDER BY created_at DESC')
      .all();

    const users = rows.map((u) => {
      const up = userPaths(u.id);
      const hasIdentity = fs.existsSync(up.certPath) && fs.existsSync(up.keyPath);

      return {
        id: u.id,
        role: u.role,
        affiliation: 'org1.department1',
        status: String(u.status || 'ACTIVE').toUpperCase(),
        fabricIdentity: hasIdentity ? 'OK' : 'MISSING_IDENTITY',
        created_at: u.created_at,
      };
    });

    return res.json({ users });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to list users', details: String(e?.message || e) });
  }
});

app.post('/admin/users/:userId/disable', requireJwt, requireAdmin, (req, res) => {
  try {
    const userId = String(req.params.userId || '').trim();
    if (!userId) {
      return res.status(400).json({ error: 'userId required' });
    }

    if (userId === ADMIN_USERNAME) {
      return res.status(400).json({ error: 'Bootstrap admin cannot be disabled' });
    }

    const existing = getUserFromDb(userId);
    if (!existing) {
      return res.status(404).json({ error: 'User not found' });
    }

    setUserStatusInDb(userId, 'DISABLED');

    return res.json({
      ok: true,
      user: {
        id: userId,
        status: 'DISABLED',
      },
    });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to disable user', details: String(e?.message || e) });
  }
});

app.post('/admin/users/:userId/enable', requireJwt, requireAdmin, (req, res) => {
  try {
    const userId = String(req.params.userId || '').trim();
    if (!userId) {
      return res.status(400).json({ error: 'userId required' });
    }

    const existing = getUserFromDb(userId);
    if (!existing) {
      return res.status(404).json({ error: 'User not found' });
    }

    setUserStatusInDb(userId, 'ACTIVE');

    return res.json({
      ok: true,
      user: {
        id: userId,
        status: 'ACTIVE',
      },
    });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to enable user', details: String(e?.message || e) });
  }
});

app.post('/admin/users/:userId/reset-password', requireJwt, requireAdmin, (req, res) => {
  try {
    const userId = String(req.params.userId || '').trim();
    const newPassword = String(req.body?.password || '');

    if (!userId || !newPassword) {
      return res.status(400).json({ error: 'userId and password required' });
    }
    if (newPassword.length < 4) {
      return res.status(400).json({ error: 'password too short' });
    }

    const existing = getUserFromDb(userId);
    if (!existing) {
      return res.status(404).json({ error: 'User not found' });
    }

    const ok = resetUserPasswordInDb(userId, newPassword);
    if (!ok) {
      return res.status(500).json({ error: 'Failed to update password in DB' });
    }

    return res.json({
      ok: true,
      user: {
        id: userId,
        role: existing.role,
        status: existing.status || 'ACTIVE',
      },
      message: 'Password updated successfully',
    });
  } catch (e) {
    return res.status(500).json({
      error: 'Failed to reset password',
      details: String(e?.message || e),
    });
  }
});


app.post('/documents/versioned', requireJwt, async (req, res) => {
  let gateway;
  try {
    const { documentId, version, contentHash, owner, metadata } = req.body;

    if (!documentId || !version || !contentHash || !owner) {
      return res.status(400).json({ error: 'documentId, version, contentHash, owner required' });
    }

    const userId = req.userId;

    gateway = newGatewayForUser(userId);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    const out = await submitTx(
      contract,
      'registerDocumentVersion',
      documentId,
      version,
      contentHash,
      owner,
      JSON.stringify(metadata ?? {})
    );

    return res.json(out);
  } catch (err) {
    const dup = parseDuplicateError(err);
    if (dup) return res.status(409).json({ alreadyRegistered: true, ...dup });

    const details = err?.details || err?.message || String(err);
    console.error('POST /documents/versioned error:', details);
    return res.status(500).json({ error: err.message, details });
  } finally {
    try {
      gateway?.close();
    } catch (_) {}
  }
});

app.get('/documents/ids', requireJwt, async (req, res) => {
  let gateway;
  try {
    const userId = req.userId;

    gateway = newGatewayForUser(userId);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    const out = await evalTx(contract, 'listDocumentIds');
    return res.json(out);
  } catch (err) {
    const details = err?.details || err?.message || String(err);
    console.error('GET /documents/ids error:', details);
    return res.status(500).json({ error: err.message, details });
  } finally {
    try {
      gateway?.close();
    } catch (_) {}
  }
});

app.get('/documents/versioned/:documentId', requireJwt, async (req, res) => {
  let gateway;
  try {
    const userId = req.userId;
    const documentId = String(req.params.documentId);

    gateway = newGatewayForUser(userId);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    const out = await evalTx(contract, 'listVersions', documentId);
    return res.json(out);
  } catch (err) {
    const details = err?.details || err?.message || String(err);
    console.error('GET /documents/versioned/:documentId error:', details);
    return res.status(500).json({ error: err.message, details });
  } finally {
    try {
      gateway?.close();
    } catch (_) {}
  }
});

app.get('/documents/latest/:documentId', requireJwt, async (req, res) => {
  let gateway;
  try {
    const userId = req.userId;
    const documentId = String(req.params.documentId);

    gateway = newGatewayForUser(userId);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    const timeline = await evalTx(contract, 'listVersions', documentId);
    const versions = Array.isArray(timeline?.versions) ? timeline.versions : [];

    if (versions.length === 0) return res.json({ exists: false, documentId });

    versions.sort((a, b) => (Number(a.version) || 0) - (Number(b.version) || 0));
    const latest = versions[versions.length - 1];

    return res.json({ exists: true, doc: latest });
  } catch (err) {
    const details = err?.details || err?.message || String(err);
    console.error('GET /documents/latest/:documentId error:', details);
    return res.status(500).json({ error: err.message, details });
  } finally {
    try {
      gateway?.close();
    } catch (_) {}
  }
});

app.get('/documents/by-hash/:hash', requireJwt, async (req, res) => {
  let gateway;
  try {
    const userId = req.userId;
    const hash = String(req.params.hash);

    gateway = newGatewayForUser(userId);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    const out = await evalTx(contract, 'getByHash', hash);
    return res.json(out);
  } catch (err) {
    const details = err?.details || err?.message || String(err);
    console.error('GET /documents/by-hash/:hash error:', details);
    return res.status(500).json({ error: err.message, details });
  } finally {
    try {
      gateway?.close();
    } catch (_) {}
  }
});

app.post('/documents/status', requireJwt, requireAdmin, async (req, res) => {
  let gateway;
  try {
    const { documentId, version, status } = req.body;
    if (!documentId || !version || !status) {
      return res.status(400).json({ error: 'documentId, version, status required' });
    }

    const userId = req.userId;

    gateway = newGatewayForUser(userId);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    const out = await submitTx(contract, 'updateStatus', documentId, version, status);
    return res.json(out);
  } catch (err) {
    const details = err?.details || err?.message || String(err);
    console.error('POST /documents/status error:', details);

    const msg = String(err?.message || '');
    if (msg.includes('Invalid status') || msg.includes('Invalid status transition') || msg.includes('required')) {
      return res.status(400).json({ error: err.message, details });
    }
    if (msg.includes('not found')) return res.status(404).json({ error: err.message, details });

    return res.status(500).json({ error: err.message, details });
  } finally {
    try {
      gateway?.close();
    } catch (_) {}
  }
});

/**
 * Startup
 */
(async () => {
  try {
    ensureBootstrapAdmin();

    await ensureBootstrapAdminFabricIdentity();

    app.listen(PORT, () => {
      console.log(`Gateway API running on http://localhost:${PORT}`);
      console.log('Using app.js:', __filename);
      console.log('BUILD_ID:', BUILD_ID);
      console.log('SQLite:', USERS_DB_PATH);
    });
  } catch (e) {
    console.error('FATAL startup error:', String(e?.message || e));
    process.exit(1);
  }
})();
app.get('/admin/status', requireJwt, requireAdmin, async (req, res) => {
  const out = {
    ok: true,
    checkedAt: new Date().toISOString(),
    caStatus: 'unknown',
    peerStatus: 'unknown',
    authStatus: req.user ? 'jwt_ok' : 'jwt_missing',
    details: {}
  };

  try {
    out.details.userId = req.userId || null;
    out.details.role = req.user?.role || null;
  } catch (e) {
    out.ok = false;
    out.details.authError = String(e?.message || e);
  }

  try {
    const { caUrl, caName, caPem } = getCaInfoFromCcp();
    out.caStatus = caUrl ? 'configured' : 'missing';
    out.details.ca = {
      caUrl,
      caName,
      tlsPemPresent: !!caPem
    };
  } catch (e) {
    out.caStatus = 'down';
    out.ok = false;
    out.details.caError = String(e?.message || e);
  }

  try {
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    const peerCfg = ccp.peers?.[peerName];
    out.details.peerConfig = {
      peerName,
      configured: !!peerCfg,
      url: peerCfg?.url || null
    };

    if (peerCfg?.url) {
      out.peerStatus = 'configured';
    } else {
      out.peerStatus = 'missing';
      out.ok = false;
    }
  } catch (e) {
    out.peerStatus = 'down';
    out.ok = false;
    out.details.ccpError = String(e?.message || e);
  }

  try {
    out.details.paths = {
      ccpPath,
      tlsCaPath,
      usersRoot
    };

    out.details.files = {
      ccpExists: fs.existsSync(ccpPath),
      tlsCaExists: fs.existsSync(tlsCaPath),
      usersRootExists: fs.existsSync(usersRoot)
    };

    if (!out.details.files.ccpExists || !out.details.files.tlsCaExists) {
      out.ok = false;
    }
  } catch (e) {
    out.ok = false;
    out.details.fileCheckError = String(e?.message || e);
  }

  try {
    const p = userPaths(req.userId);
    const hasIdentity = fs.existsSync(p.certPath) && fs.existsSync(p.keyPath);

    out.details.identity = {
      userId: req.userId,
      certPath: p.certPath,
      keyPath: p.keyPath,
      present: hasIdentity
    };

    if (!hasIdentity) {
      out.peerStatus = 'missing_identity';
      out.ok = false;
    }
  } catch (e) {
    out.peerStatus = 'down';
    out.ok = false;
    out.details.identityError = String(e?.message || e);
  }

  let gateway;
  try {
    gateway = newGatewayForUser(req.userId);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    await contract.evaluateTransaction('listDocumentIds');

    out.peerStatus = 'up';
    out.details.gatewayTest = {
      channelName,
      chaincodeName,
      peerName,
      evaluateTransaction: 'ok'
    };
  } catch (e) {
    out.peerStatus = 'down';
    out.ok = false;
    out.details.gatewayError = String(e?.details || e?.message || e);
  } finally {
    try { gateway?.close(); } catch (_) {}
  }

  return res.json(out);
});