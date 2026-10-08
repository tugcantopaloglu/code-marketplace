const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const tempRoot = fs.realpathSync(os.tmpdir());
const output = fs.mkdtempSync(path.join(tempRoot, 'marketplace-signing-keys-'));
try {
  const publicKeys = [];
  for (const role of ['collector', 'sandbox']) {
    const folder = path.join(output, role);
    const script = path.join(__dirname, `create-${role}-key.cjs`);
    execFileSync(process.execPath, [script, folder, `${role}-2026`]);
    const privatePath = path.join(folder, `${role}-private.pem`);
    const publicPath = path.join(folder, role === 'collector' ? 'publisher-policy.json' : 'sandbox-trust.json');
    const privateBytes = fs.readFileSync(privatePath);
    const configBytes = fs.readFileSync(publicPath);
    const config = JSON.parse(configBytes);
    const rawPublic = Buffer.from(config.keys[`${role}-2026`], 'base64');
    assert.equal(rawPublic.length, 32);
    assert.deepEqual(Object.keys(config).sort(), role === 'collector' ? ['allowedPublishers', 'keys'] : ['keys']);
    const key = crypto.createPrivateKey(privateBytes);
    assert.equal(key.asymmetricKeyType, 'ed25519');
    const publicKey = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: rawPublic.toString('base64url') }, format: 'jwk' });
    const message = Buffer.from(`${role} key verification`);
    assert.equal(crypto.verify(null, message, publicKey, crypto.sign(null, message, key)), true);
    publicKeys.push(rawPublic);
    assert.throws(() => execFileSync(process.execPath, [script, folder, `${role}-2026`], { stdio: 'pipe' }));
    assert.deepEqual(fs.readFileSync(privatePath), privateBytes);
    assert.deepEqual(fs.readFileSync(publicPath), configBytes);
    assert.throws(() => execFileSync(process.execPath, [script, path.join(output, 'invalid'), '../invalid'], { stdio: 'pipe' }));
    if (process.platform !== 'win32') assert.equal(fs.statSync(privatePath).mode & 0o777, 0o600);
  }
  assert.notDeepEqual(publicKeys[0], publicKeys[1]);
  process.stdout.write('Collector and sandbox keys verified; existing keys were preserved.\n');
} finally {
  if (path.dirname(fs.realpathSync(output)) !== tempRoot) throw new Error('Unexpected temporary directory');
  fs.rmSync(output, { recursive: true, force: true });
}
