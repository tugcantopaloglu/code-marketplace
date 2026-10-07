const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [mode, output, ...packages] = process.argv.slice(2);
if (mode !== '--test-only' || !output || packages.length === 0) throw new Error('Usage: --test-only OUTPUT VSIX...');
fs.mkdirSync(output, { recursive: true });
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const rawKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
fs.writeFileSync(path.join(output, 'trust.json'), JSON.stringify({ keys: { 'synthetic-test': rawKey.toString('base64') } }), { flag: 'wx' });
for (const file of packages) {
  const now = Date.now();
  const claims = {
    schemaVersion: 1,
    sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
    status: 'completed',
    verdict: 'clean',
    scanner: 'synthetic-test-not-a-malware-scan',
    scanId: crypto.randomUUID(),
    scannedAt: new Date(now - 60000).toISOString(),
    expiresAt: new Date(now + 3600000).toISOString()
  };
  const payload = Buffer.from(JSON.stringify(claims));
  const signature = crypto.sign(null, Buffer.concat([Buffer.from('code-marketplace/sandbox-report/v1\n'), payload]), privateKey);
  const envelope = { keyId: 'synthetic-test', payload: payload.toString('base64'), signature: signature.toString('base64') };
  const basename = path.basename(file, path.extname(file));
  fs.writeFileSync(path.join(output, basename + '.sandbox.json'), JSON.stringify(envelope), { flag: 'wx' });
}
process.stdout.write('Synthetic sandbox reports created for integration testing only.\n');
