import test from "node:test";
import assert from "node:assert/strict";
import { emailDomain, isAllowedEmail, normalizeEmail, parseAllowedDomains } from "../src/domain.js";

test("normalizes email and allowed domains", () => {
  assert.equal(normalizeEmail("  User@Example.COM "), "user@example.com");
  assert.deepEqual([...parseAllowedDomains("@example.com, ACME.test")], ["example.com", "acme.test"]);
});

test("accepts exact domains and rejects subdomains or lookalikes", () => {
  const allowed = parseAllowedDomains("example.com");
  assert.equal(isAllowedEmail("user@example.com", allowed), true);
  assert.equal(isAllowedEmail("user@sub.example.com", allowed), false);
  assert.equal(isAllowedEmail("user@example.com.attacker.test", allowed), false);
  assert.equal(isAllowedEmail("not-an-email", allowed), false);
  assert.equal(emailDomain("a@b@example.com"), null);
});
