const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

exports.handler = async (event) => {
  const SECRET = process.env.SEJOUR_SECRET;

  if (!SECRET) {
    return { statusCode: 500, body: 'Server configuration error' };
  }

  // Vérifier le cookie
  const cookies = {};
  const cookieHeader = event.headers.cookie || '';
  cookieHeader.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k.trim()] = v.join('=').trim();
  });

  // Token valide cette semaine ou la semaine passée (tolérance)
  const week = Math.floor(Date.now() / (7 * 24 * 3600 * 1000));
  const validTokens = [week, week - 1].map(w =>
    crypto.createHmac('sha256', SECRET).update(w.toString()).digest('hex')
  );

  if (!validTokens.includes(cookies.txorien_access)) {
    return {
      statusCode: 302,
      headers: { Location: '/infos-sejour.html?error=2' },
      body: ''
    };
  }

  // Servir le contenu protégé
  const html = fs.readFileSync(path.join(__dirname, 'infos-content.html'), 'utf-8');

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'X-Robots-Tag': 'noindex'
    },
    body: html
  };
};
