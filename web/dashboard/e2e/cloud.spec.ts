// The Cloud section, end to end: networks and a container workload created,
// watched and deleted through the dashboard. With a compute node registered
// (CI sets PF_REQUIRE_CLOUD_NODE=1) the workload must reach Running; without
// one it stays Pending and is deleted from there.

import { expect, type Page, test } from "@playwright/test";

import { OWNER, signIn, VIEWER } from "./auth";

const REQUIRE_NODE = process.env.PF_REQUIRE_CLOUD_NODE === "1";

/** Creates a project through the BFF, as the signed-in page would. */
async function createProject(page: Page, slug: string): Promise<string> {
  const id = await page.evaluate(async (projectSlug) => {
    const response = await fetch("/bff/api/core/projects", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ slug: projectSlug, name: `E2E ${projectSlug}` }),
    });
    if (response.status !== 201) throw new Error(`create project: ${response.status}`);
    return ((await response.json()) as { id: string }).id;
  }, slug);
  return id;
}

async function deleteProject(page: Page, id: string): Promise<void> {
  await page.evaluate(async (projectId) => {
    await fetch(`/bff/api/core/projects/${projectId}`, { method: "DELETE" });
  }, id);
}

/** A /24 in 10.200.0.0/16 that is unlikely to be taken by a parallel run. */
function cidr(): string {
  return `10.200.${Math.floor(Math.random() * 256)}.0/24`;
}

test("an owner creates a network and a container, watches it and deletes both", async ({ page }) => {
  test.setTimeout(240_000);
  await signIn(page, OWNER);
  const suffix = Date.now().toString(36);
  const projectId = await createProject(page, `e2e-cloud-${suffix}`);
  const networkName = `e2e-net-${suffix}`;
  const workloadName = `e2e-box-${suffix}`;

  try {
    await page.goto("/cloud");
    await expect(page.getByRole("navigation", { name: "Cloud" })).toBeVisible();

    await page.getByRole("navigation", { name: "Cloud" }).getByRole("link", { name: "Networks" }).click();
    await expect(page).toHaveURL(/\/cloud\/networks$/);
    // Selects are found by field name: a select's accessible name includes its chosen option.
    await page.locator('select[name="project_id"]').selectOption(projectId);
    await page.getByLabel("Network name").fill(networkName);
    await page.getByLabel("CIDR").fill(cidr());
    await page.getByRole("button", { name: "Create network" }).click();
    const row = page.getByTestId(`network-${networkName}`);
    await expect(row).toContainText("nat");

    await page.goto("/cloud/workloads");
    await page.locator('select[name="project_id"]').selectOption(projectId);
    await page.getByLabel("Name", { exact: true }).fill(workloadName);
    await page.locator('select[name="template"]').selectOption("alpine-sleeper");
    // The project's only network is preselected.
    await expect(page.locator('select[name="network_id"]')).toContainText(networkName);
    await page.getByRole("button", { name: "Create workload" }).click();

    await expect(page).toHaveURL(/\/cloud\/workloads\/[0-9a-f-]{36}$/);
    await expect(page.getByRole("heading", { level: 2, name: new RegExp(workloadName) })).toBeVisible();
    await expect(page.getByRole("list", { name: "Workload history" })).toContainText("created from template");

    if (REQUIRE_NODE) {
      // The page refreshes itself while the workload converges.
      await expect(page.getByRole("heading", { level: 2, name: new RegExp(workloadName) })).toContainText(
        "Running",
        { timeout: 120_000 },
      );
      await expect(page.getByRole("button", { name: "Stop" })).toBeVisible();
    }

    // Deleting needs the name typed back.
    await page.getByRole("button", { name: `Delete workload ${workloadName}` }).click();
    const confirm = page.getByRole("button", { name: "Delete workload", exact: true });
    await expect(confirm).toBeDisabled();
    await page.getByLabel(/Type .* to confirm/).fill("wrong");
    await expect(confirm).toBeDisabled();
    await page.getByLabel(/Type .* to confirm/).fill(workloadName);
    await confirm.click();
    await expect(page.getByRole("heading", { level: 2, name: new RegExp(workloadName) })).toContainText(
      "Deleted",
      { timeout: 120_000 },
    );

    await page.goto("/cloud/networks");
    await page.getByRole("button", { name: `Delete network ${networkName}` }).click();
    await page.getByLabel(/Type .* to confirm/).fill(networkName);
    await page.getByRole("button", { name: "Delete network", exact: true }).click();
    await expect(page.getByTestId(`network-${networkName}`)).toHaveCount(0);
  } finally {
    await deleteProject(page, projectId);
  }
});

test("a viewer sees cloud resources but no write actions", async ({ page }) => {
  await signIn(page, VIEWER);

  await page.goto("/cloud/workloads");
  await expect(page.getByRole("heading", { level: 1, name: "Cloud" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create workload" })).toHaveCount(0);

  await page.goto("/cloud/networks");
  await expect(page.getByRole("button", { name: "Create network" })).toHaveCount(0);

  await page.goto("/cloud/audit");
  await expect(page.getByText("You do not have access to the audit log.")).toBeVisible();

  // The API enforces the same rule, whatever the page offers.
  const status = await page.evaluate(async () => {
    const response = await fetch("/bff/api/cloud/networks", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        project_id: "00000000-0000-0000-0000-000000000000",
        name: "nope",
        kind: "nat",
        cidr: "10.9.9.0/24",
      }),
    });
    return response.status;
  });
  expect(status).toBe(403);
});
