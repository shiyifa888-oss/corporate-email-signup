export function parseAllowedDomains(value = "") {
  return new Set(
    value
      .split(",")
      .map((domain) => domain.trim().toLowerCase().replace(/^@/, ""))
      .filter(Boolean),
  );
}

export function normalizeEmail(value = "") {
  return value.trim().toLowerCase();
}

export function emailDomain(email) {
  const normalized = normalizeEmail(email);
  if ((normalized.match(/@/g) || []).length !== 1) return null;
  const at = normalized.lastIndexOf("@");
  if (at <= 0 || at === normalized.length - 1) return null;
  return normalized.slice(at + 1);
}

export function isAllowedEmail(email, allowedDomains) {
  const domain = emailDomain(email);
  return domain !== null && allowedDomains.has(domain);
}
