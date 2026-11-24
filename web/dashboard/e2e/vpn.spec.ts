// The VPN section, end to end: a device enrolled with a key pair generated
// in the browser, activated after a fresh sign-in, and revoked. Needs a
// registered gateway (CI installs one); without it enrolment answers 409.

import { expect, test } from "@playwright/test";

import { OWNER, signIn, VIEWER } from "./auth";

test("an owner enrols a device with a browser-generated key, activates and revokes it", async ({ page }) => {
  test.setTimeout(120_000);
  await signIn(page, OWNER);
  await page.goto("/vpn");
  await expect(page.getByRole("heading", { level: 1, name: "VPN" })).toBeVisible();
  await expect(page.getByText("In sync").first()).toBeVisible({ timeout: 30_000 });

  const name = `e2e-${Date.now().toString(36)}`;
  await page.getByLabel("Device name").fill(name);
  await page.getByRole("button", { name: "Enrol device" }).click();

  const result = page.getByTestId("enrolment-result");
  await expect(result).toBeVisible();
  const config = await page.getByLabel("WireGuard configuration").inputValue();
  expect(config).toMatch(/^\[Interface\]\nPrivateKey = [A-Za-z0-9+/]{43}=\n/);
  expect(config).toContain("PresharedKey = ");
  expect(config).toContain("PersistentKeepalive = 25");
  await expect(page.getByRole("link", { name: `Download pf-${name}.conf` })).toBeVisible();
  await page.getByRole("button", { name: "Done (forget the key)" }).click();
  await expect(page.getByLabel("WireGuard configuration")).toHaveCount(0);

  const row = page.getByTestId(`device-${name}`);
  await expect(row).toContainText(/Pending|Enrolled/);
  await row.getByRole("button", { name: "Activate" }).click();
  await expect(row).toContainText("Active");
  await expect(row).toContainText(/left/);

  await row.getByRole("button", { name: `Revoke device ${name}` }).click();
  await page.getByLabel(/Type .* to confirm/).fill(name);
  await page.getByRole("button", { name: "Revoke device", exact: true }).click();
  await expect(page.getByTestId(`device-${name}`)).toHaveCount(0);
});

test("a viewer sees the VPN but cannot enrol or manage policies", async ({ page }) => {
  await signIn(page, VIEWER);
  await page.goto("/vpn");
  await expect(page.getByText("cannot enrol devices")).toBeVisible();
  await expect(page.getByRole("button", { name: "Enrol device" })).toHaveCount(0);

  await page.goto("/vpn/policies");
  await expect(page.getByTestId("policy-admins-to-platform")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create policy" })).toHaveCount(0);

  await page.goto("/vpn/audit");
  await expect(page.getByText("You do not have access to the audit log.")).toBeVisible();
});
