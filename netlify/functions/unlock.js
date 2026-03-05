const crypto = require('crypto');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const params = new URLSearchParams(event.body);
  const pwd = params.get('password');

  const CORRECT_PWD = process.env.SEJOUR_PWD;
  const SECRET = process.env.SEJOUR_SECRET;

  if (!CORRECT_PWD || !SECRET) {
    return { statusCode: 500, body: 'Server configuration error' };
  }

  if (pwd !== CORRECT_PWD) {
    return {
      statusCode: 302,
      headers: { Location: '/infos-sejour.html?error=1' },
      body: ''
    };
  }

  // Token valable 7 jours : signe la semaine courante avec le secret
  const week = Math.floor(Date.now() / (7 * 24 * 3600 * 1000)).toString();
  const token = crypto.createHmac('sha256', SECRET).update(week).digest('hex');

  return {
    statusCode: 302,
    headers: {
      Location: '/sejour',
      'Set-Cookie': `txorien_access=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`
    },
    body: ''
  };
};
