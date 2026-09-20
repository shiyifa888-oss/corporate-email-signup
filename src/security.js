import { createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64);
  return `scrypt:${salt.toString("hex")}:${derived.toString("hex")}`;
}

export async function verifyPassword(password, stored) {
  const [scheme, saltHex, hashHex] = stored.split(":");
  if (scheme !== "scrypt" || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = await scrypt(password, Buffer.from(saltHex, "hex"), expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function signValue(value, secret) {
  const signature = createHmac("sha256", secret).update(value).digest("base64url");
  return `${value}.${signature}`;
}

export function verifySignedValue(signed, secret) {
  const dot = signed.lastIndexOf(".");
  if (dot < 1) return null;
  const value = signed.slice(0, dot);
  const supplied = Buffer.from(signed.slice(dot + 1), "base64url");
  const expected = createHmac("sha256", secret).update(value).digest();
  return supplied.length === expected.length && timingSafeEqual(supplied, expected) ? value : null;
}
