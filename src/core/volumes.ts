import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function isLikelySystemVolume(p: string): boolean {
  try {
    return fs.existsSync(path.join(p, "System")) && fs.existsSync(path.join(p, "Library"));
  } catch {
    return true;
  }
}

function listDirMounts(root: string): string[] {
  if (!fs.existsSync(root)) return [];
  try {
    return fs
      .readdirSync(root)
      .filter((name) => !name.startsWith("."))
      .map((name) => path.join(root, name))
      .filter((p) => {
        try {
          return fs.statSync(p).isDirectory() && !isLikelySystemVolume(p);
        } catch {
          return false;
        }
      });
  } catch {
    return [];
  }
}

function windowsDrives(): string[] {
  const drives: string[] = [];
  const system = (process.env.SystemDrive || "C:").toUpperCase();
  for (let code = 65; code <= 90; code++) {
    const letter = String.fromCharCode(code);
    const root = `${letter}:\\`;
    if (`${letter}:` === system) continue;
    try {
      if (fs.existsSync(root) && fs.statSync(root).isDirectory()) drives.push(root);
    } catch {
      /* skip */
    }
  }
  return drives;
}

/**
 * Removable / external volume mount points suitable for USB backup.
 * macOS: /Volumes/* (minus system). Linux: /run/media/$USER, /media/$USER, /mnt/*.
 * Windows: non-system drive letters.
 */
export function mountedVolumes(platform = process.platform): string[] {
  if (platform === "darwin") {
    return listDirMounts("/Volumes");
  }
  if (platform === "linux") {
    const user = os.userInfo().username;
    const seen = new Set<string>();
    const out: string[] = [];
    for (const root of [`/run/media/${user}`, `/media/${user}`, "/mnt"]) {
      for (const p of listDirMounts(root)) {
        const key = path.resolve(p);
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(p);
      }
    }
    return out;
  }
  if (platform === "win32") {
    return windowsDrives();
  }
  return [];
}

/** Resolve a user-supplied volume name or path against platform mount roots. */
export function resolveVolumePath(target: string, platform = process.platform): string {
  if (path.isAbsolute(target) || /^[A-Za-z]:[\\/]/.test(target)) return target;
  if (fs.existsSync(path.join(process.cwd(), target))) {
    return path.join(process.cwd(), target);
  }
  if (platform === "darwin") return path.join("/Volumes", target);
  if (platform === "linux") {
    const user = os.userInfo().username;
    for (const root of [`/run/media/${user}`, `/media/${user}`, "/mnt"]) {
      const candidate = path.join(root, target);
      if (fs.existsSync(candidate)) return candidate;
    }
    return path.join(`/media/${user}`, target);
  }
  if (platform === "win32") {
    const withSlash = target.endsWith("\\") || target.endsWith("/") ? target : `${target}\\`;
    if (/^[A-Za-z]:/.test(withSlash)) return withSlash;
    return `${target}:\\`;
  }
  return target;
}

export function volumesRootLabel(platform = process.platform): string {
  if (platform === "darwin") return "/Volumes";
  if (platform === "linux") return "/media or /mnt";
  if (platform === "win32") return "drive letters";
  return "mounted volumes";
}
