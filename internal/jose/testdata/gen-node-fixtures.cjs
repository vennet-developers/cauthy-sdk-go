// Writes node-fixtures.json with @cauthyhq/node's own crypto (jose 5.10.0):
// the keys HKDF derives from a test root key, a session sealed with them and
// with SHA-256 of a test secret, and a key made and sealed as its key store
// keeps it. Test values only.
//
//   cd ../cauthy-sdk-node && node ../cauthy-sdk-go/internal/jose/testdata/gen-node-fixtures.cjs \
//     > ../cauthy-sdk-go/internal/jose/testdata/node-fixtures.json
const jose = require(process.cwd() + '/node_modules/jose')
const { webcrypto: crypto } = require('node:crypto')
const enc = new TextEncoder()
async function derive(root, purpose) {
  const ikm = await crypto.subtle.importKey('raw', enc.encode(root), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(`pact/${purpose}/v1`) }, ikm, 256)
  return new Uint8Array(bits)
}
const hex = u => Buffer.from(u).toString('hex')
;(async () => {
  const root = 'acme-root-key-for-tests-only-0123456789'
  const out = {}
  for (const p of ['seal', 'cookie', 'flow']) out[p] = hex(await derive(root, p))
  const secret = 'acme-secret-for-tests-only-0123456789abcdef'
  out.secretKey = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(secret))))
  const stored = { at: 'at-1', rt: 'rt-1', exp: 1767226440, u: { id: '5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c', email: 'ana@example.com', name: 'Ana', emailVerified: true, restricted: false }, tid: '8a6e0804-2bd0-4672-b79a-d97027f5f2a1', roles: ['member'], p: 1 }
  const sealWith = async (v, key) => new jose.CompactEncrypt(enc.encode(JSON.stringify(v))).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).encrypt(key)
  out.cookieSealed = await sealWith(stored, await derive(root, 'cookie'))
  out.secretSealed = await sealWith(stored, new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(secret))))
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048, extractable: true })
  const publicJwk = await jose.exportJWK(publicKey)
  const kid = await jose.calculateJwkThumbprint(publicJwk)
  out.storedKey = { kid, publicJwk, sealed: await sealWith(await jose.exportJWK(privateKey), await derive(root, 'seal')), createdAt: '2026-01-01T00:00:00.000Z' }
  console.log(JSON.stringify(out, null, 2))
})()
