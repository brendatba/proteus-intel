const { put, list } = require('@vercel/blob');
const crypto = require('crypto');

function verifyToken(token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const [payloadB64, signature] = parts;
  const secret = process.env.JWT_SECRET || 'proteus-default-secret';
  const expected = crypto
    .createHmac('sha256', secret)
    .update(Buffer.from(payloadB64, 'base64').toString())
    .digest('hex');

  if (signature !== expected) return false;

  try {
    const data = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
    if (data.exp < Date.now()) return false;
    return true;
  } catch {
    return false;
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'GET') {
    try {
      const { blobs } = await list({ prefix: 'content/' });
      const contentBlob = blobs.find(
        (b) => b.pathname === 'content/site-content.json'
      );
      if (!contentBlob) {
        return res.json({});
      }
      const response = await fetch(contentBlob.url);
      const content = await response.json();
      return res.json(content);
    } catch {
      return res.json({});
    }
  }

  if (req.method === 'PUT') {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!verifyToken(token)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      const content = req.body;
      await put('content/site-content.json', JSON.stringify(content), {
        access: 'public',
        addRandomSuffix: false,
        contentType: 'application/json',
      });
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to save content' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
