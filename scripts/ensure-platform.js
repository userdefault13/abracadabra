#!/usr/bin/env node
const hints = {
  darwin: "Touch ID + Keychain (default)",
  linux: "keytar + Secret Service (libsecret); fallback: ABRA_KEYSTORE=passphrase-file",
  win32: "keytar + Credential Vault; fallback: ABRA_KEYSTORE=passphrase-file",
};

const hint = hints[process.platform];
if (hint) {
  console.log(`abracadabra: ${process.platform} — ${hint}`);
} else {
  console.warn(
    `abracadabra: unsupported platform ${process.platform} — try ABRA_KEYSTORE=passphrase-file. See docs/CROSS-PLATFORM.md`,
  );
}
