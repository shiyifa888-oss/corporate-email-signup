import test from "node:test";
import assert from "node:assert/strict";
import { hashPassword, signValue, verifyPassword, verifySignedValue } from "../src/security.js";

test("password hashing and verification", async () => {
  const stored = await hashPassword("a secure password");
  assert.equal(await verifyPassword("a secure password", stored), true);
  assert.equal(await verifyPassword("wrong password", stored), false);
});

test("signed values reject tampering", () => {
  const signed = signValue("user@example.com", "test-secret");
  assert.equal(verifySignedValue(signed, "test-secret"), "user@example.com");
  assert.equal(verifySignedValue(`${signed}x`, "test-secret"), null);
});
