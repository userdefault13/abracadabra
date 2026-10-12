import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";

export interface EphemeralTls {
  key: string;
  cert: string;
  /** Full SHA-256 fingerprint of the DER cert (32 colon-separated uppercase hex pairs). */
  fingerprint: string;
}

function fingerprintFromPem(certPem: string): string {
  const b64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(b64, "base64");
  return fingerprintFromDer(der);
}

/** Full SHA-256 of DER bytes as `AA:BB:…` (32 pairs). */
export function fingerprintFromDer(der: Buffer): string {
  const hash = crypto.createHash("sha256").update(der).digest("hex");
  const pairs = hash.match(/.{2}/g) ?? [];
  return pairs.join(":").toUpperCase();
}

/** Generate a short-lived self-signed cert via openssl (macOS/Linux; Windows if openssl is on PATH). */
/**
 * X.509 CN must be ≤ 64 chars and must not contain "/" or "=" (openssl -subj syntax).
 * Long macOS hostnames (e.g. CI runners, "*.local" names) otherwise make openssl fail.
 */
export function sanitizeCommonName(commonName: string): string {
  const cleaned = commonName.replace(/[^A-Za-z0-9.-]/g, "-").slice(0, 64).replace(/^[-.]+|[-.]+$/g, "");
  return cleaned || "abracadabra-lan";
}

export function createEphemeralTls(commonName = "abracadabra-lan", opts: { days?: number } = {}): EphemeralTls {
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
        String(opts.days ?? 1),
        "-nodes",
        "-subj",
        `/CN=${sanitizeCommonName(commonName)}`,
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

/**
 * Open a TLS socket and verify the peer cert fingerprint BEFORE any application
 * bytes (and thus any PIN) are written. Node skips checkServerIdentity when
 * rejectUnauthorized is false, so we verify on secureConnect ourselves.
 */
export function connectPinnedTls(
  host: string,
  port: number,
  expectedFingerprint: string,
): Promise<{ socket: tls.TLSSocket; peerFingerprint: string }> {
  return new Promise((resolve, reject) => {
    const isIp = net.isIP(host) !== 0;
    const socket = tls.connect({
      host,
      port,
      servername: isIp ? undefined : host,
      rejectUnauthorized: false,
    });
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      reject(err);
    };
    socket.once("error", (err) => fail(err instanceof Error ? err : new Error(String(err))));
    socket.once("secureConnect", () => {
      try {
        const cert = socket.getPeerCertificate(true);
        if (!cert?.raw) {
          fail(new Error("TLS fingerprint unavailable — refusing unauthenticated peer"));
          return;
        }
        const peerFp = fingerprintFromDer(cert.raw as Buffer);
        if (!fingerprintsMatch(expectedFingerprint, peerFp)) {
          fail(
            new Error(
              `TLS fingerprint mismatch (expected ${expectedFingerprint}, got ${peerFp}) — PIN not sent`,
            ),
          );
          return;
        }
        settled = true;
        resolve({ socket, peerFingerprint: peerFp });
      } catch (err) {
        fail(err instanceof Error ? err : new Error(String(err)));
      }
    });
  });
}

/**
 * Compare TLS fingerprints.
 * - expected with 64 hex chars → exact match against actual (always full)
 * - expected with exactly 16 hex chars (legacy short) → prefix match + stderr warning
 * - any other length → false
 */
export function fingerprintsMatch(expected: string, actual: string): boolean {
  const norm = (s: string) => s.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  const ne = norm(expected);
  const na = norm(actual);
  if (!ne || !na) return false;
  if (ne.length === 64) {
    return ne === na;
  }
  if (ne.length === 16) {
    if (na.startsWith(ne)) {
      console.error(
        "WARNING: legacy short TLS fingerprint — upgrade the host",
      );
      return true;
    }
    return false;
  }
  return false;
}
