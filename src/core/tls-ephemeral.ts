import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface EphemeralTls {
  key: string;
  cert: string;
  /** Short SHA-256 fingerprint of the DER cert (colon-separated hex pairs, first 8 groups). */
  fingerprint: string;
}

function fingerprintFromPem(certPem: string): string {
  const b64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(b64, "base64");
  const hash = crypto.createHash("sha256").update(der).digest("hex");
  const pairs = hash.match(/.{2}/g) ?? [];
  return pairs.slice(0, 8).join(":").toUpperCase();
}

/** Generate a short-lived self-signed cert via openssl (macOS/Linux; Windows if openssl is on PATH). */
export function createEphemeralTls(commonName = "abracadabra-lan"): EphemeralTls {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-tls-"));
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");
  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        keyPath,
        "-out",
        certPath,
        "-days",
        "1",
        "-nodes",
        "-subj",
        `/CN=${commonName}`,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const key = fs.readFileSync(keyPath, "utf8");
    const cert = fs.readFileSync(certPath, "utf8");
    return { key, cert, fingerprint: fingerprintFromPem(cert) };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

export function fingerprintOfPem(certPem: string): string {
  return fingerprintFromPem(certPem);
}

export function fingerprintsMatch(a: string, b: string): boolean {
  const norm = (s: string) => s.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  const na = norm(a);
  const nb = norm(b);
  if (!na || !nb) return false;
  const len = Math.min(na.length, nb.length, 16); // compare at least first 8 bytes
  return na.slice(0, len) === nb.slice(0, len);
}
