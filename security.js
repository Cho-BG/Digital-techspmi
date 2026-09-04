import crypto from 'crypto';

const SCRYPT_KEY_LENGTH = 64;

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, SCRYPT_KEY_LENGTH).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

export function isPasswordHash(value) {
  return /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{128}$/.test(String(value));
}

export function verifyPassword(password, storedValue) {
  if (!isPasswordHash(storedValue)) return false;
  const [, salt, expectedHex] = storedValue.split('$');
  const actual = crypto.scryptSync(String(password), salt, SCRYPT_KEY_LENGTH);
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function isValidPassword(password) {
  return /^[A-Za-z0-9]{8,10}$/.test(String(password));
}

export function generatePassword(length = 9) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(length);
  return Array.from(bytes, byte => alphabet[byte % alphabet.length]).join('');
}

export function encryptPassword(password, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(password), 'utf8'), cipher.final()]);
  return `v1$${iv.toString('base64')}$${cipher.getAuthTag().toString('base64')}$${encrypted.toString('base64')}`;
}

export function decryptPassword(value, key) {
  const [version, iv, tag, encrypted] = String(value).split('$');
  if (version !== 'v1' || !iv || !tag || !encrypted) throw new Error('Invalid password vault value');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64')), decipher.final()]).toString('utf8');
}
