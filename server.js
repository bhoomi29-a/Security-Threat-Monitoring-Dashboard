const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'threats.json');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));

const seedThreats = [
  { id: 'TH-1042', title: 'Repeated failed login attempts', sourceIp: '192.0.2.41', type: 'Authentication', severity: 'High', status: 'Open', asset: 'Admin Portal', description: 'Multiple failed sign-in attempts detected in a short period.', createdAt: new Date(Date.now()-5*60000).toISOString() },
  { id: 'TH-1041', title: 'Suspicious outbound traffic', sourceIp: '198.51.100.18', type: 'Network', severity: 'Critical', status: 'Investigating', asset: 'Workstation-07', description: 'Unusual outbound traffic volume flagged by the demo sensor.', createdAt: new Date(Date.now()-22*60000).toISOString() },
  { id: 'TH-1040', title: 'Potential SQL injection pattern', sourceIp: '203.0.113.76', type: 'Web Attack', severity: 'High', status: 'Open', asset: 'Student Portal', description: 'A request matched a sample SQL injection detection rule.', createdAt: new Date(Date.now()-48*60000).toISOString() },
  { id: 'TH-1039', title: 'Endpoint antivirus warning', sourceIp: '192.0.2.88', type: 'Endpoint', severity: 'Medium', status: 'Resolved', asset: 'Lab-PC-12', description: 'A demo endpoint warning was reviewed and marked resolved.', createdAt: new Date(Date.now()-2*3600000).toISOString() },
  { id: 'TH-1038', title: 'Port scan behaviour detected', sourceIp: '198.51.100.53', type: 'Network', severity: 'Medium', status: 'Investigating', asset: 'Gateway-01', description: 'Several ports were contacted in a short interval in sample telemetry.', createdAt: new Date(Date.now()-4*3600000).toISOString() },
  { id: 'TH-1037', title: 'Unusual account activity', sourceIp: '203.0.113.21', type: 'Authentication', severity: 'Low', status: 'Resolved', asset: 'Email Service', description: 'A low-priority sample alert for unusual account activity.', createdAt: new Date(Date.now()-7*3600000).toISOString() },
  { id: 'TH-1036', title: 'New device on network', sourceIp: '192.0.2.109', type: 'Network', severity: 'Low', status: 'Open', asset: 'Campus Wi-Fi', description: 'A device not seen before appeared in the sample network inventory.', createdAt: new Date(Date.now()-10*3600000).toISOString() }
];

let collection = null;
let localThreats = [];

function saveLocal() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(localThreats, null, 2));
}
function loadLocal() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(DATA_FILE)) {
    try { localThreats = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
    catch { localThreats = [...seedThreats]; saveLocal(); }
  } else {
    localThreats = [...seedThreats];
    saveLocal();
  }
}
async function allThreats() {
  return collection ? collection.find({}).sort({ createdAt: -1 }).toArray() : [...localThreats].sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt));
}
async function findThreat(id) {
  return collection ? collection.findOne({ id }) : localThreats.find(t => t.id === id);
}
async function insertThreat(threat) {
  if (collection) await collection.insertOne(threat);
  else { localThreats.push(threat); saveLocal(); }
}
async function updateThreat(id, patch) {
  if (collection) {
    const result = await collection.findOneAndUpdate({ id }, { $set: patch }, { returnDocument: 'after' });
    return result;
  }
  const index = localThreats.findIndex(t => t.id === id);
  if (index < 0) return null;
  localThreats[index] = { ...localThreats[index], ...patch };
  saveLocal();
  return localThreats[index];
}
async function removeThreat(id) {
  if (collection) return (await collection.deleteOne({ id })).deletedCount > 0;
  const before = localThreats.length;
  localThreats = localThreats.filter(t => t.id !== id);
  if (localThreats.length !== before) saveLocal();
  return localThreats.length !== before;
}

const severities = ['Low', 'Medium', 'High', 'Critical'];
const statuses = ['Open', 'Investigating', 'Resolved'];
const types = ['Authentication', 'Network', 'Web Attack', 'Endpoint', 'Malware', 'Other'];

app.get('/api/health', (req, res) => res.json({ status: 'ok', storage: collection ? 'mongodb' : 'local-json', time: new Date().toISOString() }));

app.get('/api/threats', async (req, res, next) => {
  try {
    let threats = await allThreats();
    const { search, severity, status, type } = req.query;
    if (severity && severities.includes(severity)) threats = threats.filter(t => t.severity === severity);
    if (status && statuses.includes(status)) threats = threats.filter(t => t.status === status);
    if (type && types.includes(type)) threats = threats.filter(t => t.type === type);
    if (search) {
      const q = String(search).toLowerCase().slice(0, 100);
      threats = threats.filter(t => [t.id,t.title,t.sourceIp,t.asset,t.type].some(v => String(v || '').toLowerCase().includes(q)));
    }
    res.json({ data: threats, total: threats.length });
  } catch (err) { next(err); }
});

app.get('/api/stats', async (req, res, next) => {
  try {
    const threats = await allThreats();
    const bySeverity = Object.fromEntries(severities.map(s => [s, threats.filter(t => t.severity === s).length]));
    const byType = Object.fromEntries(types.map(t => [t, threats.filter(x => x.type === t).length]).filter(([,n]) => n));
    res.json({
      total: threats.length,
      open: threats.filter(t => t.status === 'Open').length,
      investigating: threats.filter(t => t.status === 'Investigating').length,
      resolved: threats.filter(t => t.status === 'Resolved').length,
      critical: threats.filter(t => t.severity === 'Critical' && t.status !== 'Resolved').length,
      bySeverity, byType,
      recent: threats.slice(0, 5)
    });
  } catch (err) { next(err); }
});

app.post('/api/threats', async (req, res, next) => {
  try {
    const body = req.body || {};
    const required = ['title', 'sourceIp', 'type', 'severity', 'asset', 'description'];
    for (const field of required) {
      if (typeof body[field] !== 'string' || !body[field].trim()) {
        return res.status(400).json({ error: `${field} is required.` });
      }
      if (body[field].length > (field === 'description' ? 500 : 120)) {
        return res.status(400).json({ error: `${field} is too long.` });
      }
    }
    if (!types.includes(body.type)) return res.status(400).json({ error: 'Invalid threat type.' });
    if (!severities.includes(body.severity)) return res.status(400).json({ error: 'Invalid severity.' });
    const threat = {
      id: `TH-${Date.now().toString().slice(-7)}`,
      title: body.title.trim(),
      sourceIp: body.sourceIp.trim(),
      type: body.type,
      severity: body.severity,
      status: 'Open',
      asset: body.asset.trim(),
      description: body.description.trim(),
      createdAt: new Date().toISOString()
    };
    await insertThreat(threat);
    res.status(201).json({ message: 'Threat created.', data: threat });
  } catch (err) { next(err); }
});

app.patch('/api/threats/:id', async (req, res, next) => {
  try {
    const { status, severity } = req.body || {};
    const patch = {};
    if (status !== undefined) {
      if (!statuses.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
      patch.status = status;
    }
    if (severity !== undefined) {
      if (!severities.includes(severity)) return res.status(400).json({ error: 'Invalid severity.' });
      patch.severity = severity;
    }
    if (!Object.keys(patch).length) return res.status(400).json({ error: 'Provide a valid status or severity.' });
    const updated = await updateThreat(req.params.id, patch);
    if (!updated) return res.status(404).json({ error: 'Threat not found.' });
    res.json({ message: 'Threat updated.', data: updated });
  } catch (err) { next(err); }
});

app.delete('/api/threats/:id', async (req, res, next) => {
  try {
    const removed = await removeThreat(req.params.id);
    if (!removed) return res.status(404).json({ error: 'Threat not found.' });
    res.json({ message: 'Threat deleted.' });
  } catch (err) { next(err); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

async function start() {
  const uri = process.env.MONGODB_URI;
  if (uri) {
    try {
      const client = new MongoClient(uri);
      await client.connect();
      const db = client.db(process.env.MONGODB_DB || 'security_monitor');
      collection = db.collection('threats');
      const count = await collection.countDocuments();
      if (count === 0) await collection.insertMany(seedThreats);
      console.log('Connected to MongoDB.');
    } catch (err) {
      console.error('MongoDB connection failed; using local JSON storage instead:', err.message);
      loadLocal();
    }
  } else {
    loadLocal();
    console.log('Using local JSON storage. Set MONGODB_URI to use MongoDB.');
  }
  app.listen(PORT, () => console.log(`Security Threat Monitor running at http://localhost:${PORT}`));
}
start();
