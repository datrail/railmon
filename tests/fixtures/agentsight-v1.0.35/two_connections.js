// One thread, two TLS connections: /slow is sent first, /fast finishes first.
// Captured as ssl.two-connections.jsonl (README.md); only the first round is kept.
const https = require('https');
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const port = process.argv[2];
function post(path, agent) {
  return new Promise((resolve) => {
    const req = https.request({ host: '127.0.0.1', port, path, method: 'POST', agent,
      headers: { 'content-type': 'application/json' } }, (res) => {
      let body = ''; res.on('data', (d) => body += d); res.on('end', () => resolve(body.length));
    });
    req.end(JSON.stringify({ path }));
  });
}
(async () => {
  await new Promise((r) => setTimeout(r, 3000)); // let the probe attach
  for (let round = 0; round < 3; round++) {
    const a = new https.Agent({ keepAlive: true }), b = new https.Agent({ keepAlive: true });
    const slow = post('/slow', a);
    await new Promise((r) => setTimeout(r, 100));
    await Promise.all([slow, post('/fast', b)]);
    a.destroy(); b.destroy();
  }
  console.log('client done');
})();
