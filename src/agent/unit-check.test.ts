import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { checkUnitNetlink } from "./unit-check.js";

const SHIPPED_UNIT = fileURLToPath(
  new URL("../../packaging/linux/abra-agent.service", import.meta.url),
);

describe("packaging/linux/abra-agent.service", () => {
  const text = fs.readFileSync(SHIPPED_UNIT, "utf8");

  it("allows AF_NETLINK (ss sock_diag peer check) and AF_UNIX", () => {
    const lines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.startsWith("RestrictAddressFamilies="));
    expect(lines).toHaveLength(1);
    const families = lines[0].slice("RestrictAddressFamilies=".length).split(/\s+/);
    expect(families).toContain("AF_NETLINK");
    expect(families).toContain("AF_UNIX");
    expect(families).not.toContain("AF_INET");
    expect(checkUnitNetlink([text])).toEqual({ status: "ok" });
  });

  it("tells upgraders to daemon-reload + restart", () => {
    expect(text).toContain("systemctl --user daemon-reload && systemctl --user restart abra-agent");
  });
});

describe("checkUnitNetlink", () => {
  it("flags the pre-fix unit", () => {
    expect(checkUnitNetlink(["[Service]\nRestrictAddressFamilies=AF_UNIX\n"])).toEqual({
      status: "missing_netlink",
      families: ["AF_UNIX"],
    });
  });

  it("ignores commented lines", () => {
    expect(
      checkUnitNetlink(["# RestrictAddressFamilies=AF_UNIX AF_NETLINK\nRestrictAddressFamilies=AF_UNIX\n"]),
    ).toMatchObject({ status: "missing_netlink" });
  });

  it("allow-lists accumulate across drop-ins; empty assignment resets", () => {
    expect(
      checkUnitNetlink(["RestrictAddressFamilies=AF_UNIX", "RestrictAddressFamilies=AF_NETLINK"]),
    ).toEqual({ status: "ok" });
    expect(
      checkUnitNetlink(["RestrictAddressFamilies=AF_UNIX", "RestrictAddressFamilies="]),
    ).toEqual({ status: "unrestricted" });
  });

  it("deny-list containing AF_NETLINK is flagged; none is flagged", () => {
    expect(checkUnitNetlink(["RestrictAddressFamilies=~AF_NETLINK AF_PACKET"])).toMatchObject({
      status: "missing_netlink",
    });
    expect(checkUnitNetlink(["RestrictAddressFamilies=none"])).toMatchObject({
      status: "missing_netlink",
    });
  });
});
