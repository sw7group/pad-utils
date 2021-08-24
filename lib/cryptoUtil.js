const crypto = require('crypto');
const fs = require('fs');

/** @typedef {import('crypto').KeyObject} KeyObject */
/**
 * @typedef {Object} symCiphertext
 * @property {Buffer} ciphertext
 * @property {Buffer} iv
 */
/**
 * @typedef {Object} hybridCiphertext
 * @property {symCiphertext} encryptedMessage
 * @property {Buffer} encryptedEphemeralKey
 */

/**
 * Parse a public key from a pem string
 * @param {string} pem - pem format string,
 * e.g. -----BEGIN PUBLIC KEY-----......-----END PUBLIC KEY-----
 * @return {KeyObject} a crypto key object
 */
function parsePublicKey(pem) {
  return crypto.createPublicKey(pem);
}
exports.parsePublicKey = parsePublicKey;

/**
 * Parse a private key from a pem string
 * @param {string} pem - pem format string,
 * e.g. -----BEGIN PRIVATE KEY-----......-----END PRIVATE KEY-----
 * @return {KeyObject} a crypto key object
 */
function parsePrivateKey(pem) {
  return crypto.createPrivateKey(pem);
};
exports.parsePrivateKey = parsePrivateKey;

/**
 * Parse and return a PEM private key file in local file system
 * @param {string} path - path to the PEM file
 * @return {KeyObject} the crypto private key object
 */
exports.getPem = (path) => {
  if (!fs.existsSync(path)) {
    throw new Error(`PEM file not found at ${path}`);
  }
  const pemFile = fs.readFileSync(path, 'utf8');
  return parsePrivateKey(pemFile);
};

/**
 * Perform asymmetric encryption
 * @param {*} d - data to be encrypted
 * @param {KeyObject} k - public key object
 * @return {Buffer} the ciphertext as a bytes string
 */
function encryptAsym(d, k) {
  return crypto.publicEncrypt(k, d);
}
exports.encryptAsym = encryptAsym;

/**
 * Perform asymmetric decryption
 * @param {Buffer | Object} c - the ciphertext
 * @param {KeyObject} k - private key object
 * @return {*}
 */
function decryptAsym(c, k) {
  if (typeof(c) === 'string') {
    c = Buffer.from(c, 'base64');
  }
  if (c.encryptedEphemeralKey != null) {
    return decryptHybrid(c, k);
  }
  return crypto.privateDecrypt(k, c);
}
exports.decryptAsym = decryptAsym;

/**
 * Perform symmetric encryption
 * @param {string} d - data to be encrypted
 * @param {Buffer} k - the symmetric key
 * @return {symCiphertext} the ciphertext
 */
function encryptSym(d, k) {
  return encryptAES(d, k);
}
exports.encryptSym = encryptSym;

/**
 * Perform symmetric decryption
 * @param {symCiphertext} c
 * @param {Buffer} k - the symmetric key
 * @return {string}
 */
function decryptSym(c, k) {
  return decryptAES(c, k);
}
exports.decryptSym = decryptSym;

/**
 * Perform AES-CBC-128 encryption
 * @param {string} d - data to be encrypted as string
 * @param {Buffer} k - the symmetric key as bytes string
 * @return {symCiphertext}
 */
function encryptAES(d, k) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', k, iv);
  cipher.update(d, 'utf8');
  const ciphertext = cipher.final();
  return {
    ciphertext: ciphertext,
    iv: iv,
  };
}

/**
 * Perform AES-CBC-128 decryption
 * @param {symCiphertext} c - the ciphertext
 * @param {Buffer} k - the symmetric key
 * @return {string}
 */
function decryptAES(c, k) {
  const decipher = crypto.createDecipheriv('aes-128-cbc', k, c.iv);
  decipher.update(c.ciphertext);
  return decipher.final('utf8');
}

/**
 * Perform asymmetric encryption on large data object
 * @param {string} d - the data to be encrypted
 * @param {KeyObject} k - public key object
 * @return {hybridCiphertext}
 */
exports.encryptHybrid = (d, k) => {
  const key = crypto.randomBytes(16);
  const ciphertext = encryptSym(d, key);
  const keyEncrypted = encryptAsym(key, k);
  return {
    encryptedMessage: ciphertext,
    encryptedEphemeralKey: keyEncrypted,
  };
};

/**
 * Perform asymmetric decryption on large data object
 * @param {hybridCiphertext} c
 * @param {KeyObject} k - private key object
 * @return {string}
 */
function decryptHybrid(c, k) {
  const key = decryptAsym(c.encryptedEphemeralKey, k);
  const d = decryptSym(c.encryptedMessage, key);
  return d;
};
exports.decryptHybrid = decryptHybrid;

/**
 * Perform SHA256 on the inputs
 * @param {...(string|Buffer)} D - to be hashed, as strings or byte strings
 * @return {Buffer} the digest
 */
exports.hash = (...D) => {
  const sha256 = crypto.createHash('sha256');
  // digest the inputs in order
  for (const d of D) {
    sha256.update(d);
  }
  return sha256.digest();
};

/**
 * Perform XOR on two byte strings
 * @param {Buffer} a - first byte string
 * @param {Buffer} b - second byte string
 * @return {Buffer} a byte string that is XOR of the inputs
 */
exports.xor = (a, b) => {
  // reject if the byte strings have different lengths
  if (a.length !== b.length) {
    throw new Error(`lengths mismatch in XOR (${a.length}, ${b.length})`);
  }
  const result = a.map((byte, i) => byte ^ b[i]);

  return Buffer.from(result);
};

/**
 * Sign a message with a private key
 * @param {string|Buffer} data - data to be signed
 * @param {KeyObject} privateKey - crypto private key
 * @return {Buffer}
 */
exports.sign = (data, privateKey) => {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  const signature = sign.sign(privateKey);
  return signature;
};

/**
 * Verify a signature with a public key
 * @param {string|Buffer} data
 * @param {string|KeyObject} publicKey - crypto public key
 * @param {string|Buffer} signature
 * @return {boolean}
 */
exports.verify = (data, publicKey, signature) => {
  if (typeof signature === 'string') {
    signature = Buffer.from(signature, 'base64');
  }
  const verify = crypto.createVerify('SHA256');
  verify.update(data);
  verify.end();
  const verification = verify.verify(publicKey, signature);
  return verification;
};

/**
 * Generate random bytes
 * @param {number} n
 * @return {Buffer}
 */
exports.randomBytes = (n) => {
  return crypto.randomBytes(n);
};

/**
 * Transform a valid base64-encoded string into a base64url-encoded string
 * @param {string} s
 * @return {string}
 */
exports.base64ToBase64Url = (s) => {
  s = s.replace(/\//g, '_');
  s = s.replace(/\+/g, '-');
  s = s.replace(/\=/g, '');
  return s;
};

/**
 * Transform a valid base64url-encoded string into a base64-encoded string
 * @param {string} s
 * @return {string}
 */
exports.base64UrlToBase64 = (s) => {
  s = s.replace(/\-/g, '+');
  s = s.replace(/\_/g, '/');
  switch (s.length %4 ) {
    case 3:
      return s + '=';
    case 2:
      return s + '==';
    default:
      return s;
  }
};
