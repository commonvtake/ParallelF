// The Network Monitoring section, end to end. CI installs a sensor and runs
// `make verify-netguard` before these tests, so real alerts exist.

import { expect, test } from "@playwright/test";

import { OWNER, signIn, VIEWER } from "./auth";

test("an owner sees the sensor and alerts, opens an incident and adds evidence", async ({ page }) => {
  test.setTimeout(90_000);
  await signIn(page, OWNER);
  await page.goto("/network");
  await expect(page.getByRole("heading", { level: 1, name: "Network Monitoring" })).toBeVisible();
  await expect(page.locator('[data-testid^="sensor-"]').first()).toContainText("Reporting");
  await expect(page.locator('[data-testid^="sensor-"]').first()).toContainText("wg-pf0");

  const title = `e2e incident ${Date.now().toString(36)}`;
  await page.getByRole("link", { name: "Incidents" }).click();
  await page.getByLabel("Incident title").fill(title);
  await page.getByRole("button", { name: "Open incident" }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();

  await page.getByLabel("Evidence name").fill("e2e note");
  await page.getByLabel("Evidence text").fill("Observed during the end-to-end test.");
  await page.getByRole("button", { name: "Add evidence" }).click();
  await expect(page.getByTestId("evidence-e2e note")).toContainText("sha256");
  await expect(page.getByTestId("evidence-verification")).toContainText("Digests verified");

  await page.getByLabel("Status").selectOption("resolved");
  await page.getByLabel("Timeline note").fill("Closed by the end-to-end test.");
  await page.getByRole("button", { name: "Update incident" }).click();
  await expect(page.getByText("A resolved incident takes no new evidence")).toBeVisible();
});

test("an owner cannot issue a scope outside ParallelF's networks", async ({ page }) => {
  await signIn(page, OWNER);
  await page.goto("/network/scopes");
  await page.getByLabel("Scope name").fill("home-network");
  await page.getByLabel("Networks (CIDRs)").fill("192.168.1.0/24");
  await page.getByLabel("Authorization").fill("Trying a range the platform does not own.");
  await page.getByRole("button", { name: "Issue scope" }).click();
  await expect(page.getByRole("alert")).toContainText(/not inside a ParallelF network|sign-in/);
});

test("a viewer sees alerts but cannot triage, issue scopes or read the audit trail", async ({ page }) => {
  await signIn(page, VIEWER);
  await page.goto("/network");
  await expect(page.getByRole("heading", { level: 1, name: "Network Monitoring" })).toBeVisible();
  await page.goto("/network/incidents");
  await expect(page.getByRole("button", { name: "Open incident" })).toHaveCount(0);
  await page.goto("/network/scopes");
  await expect(page.getByText("Only owners and admins can issue discovery scopes.")).toBeVisible();
  await page.goto("/network/audit");
  await expect(page.getByText("You do not have access to the audit log.")).toBeVisible();
});
