// End-to-end tests against the running local stack (`make up`).
//
// They sign in through the real identity provider with the development
// users defined in deploy/keycloak/realm/parallelf-realm.json.

import { expect, type Page, test } from "@playwright/test";

const OWNER = { username: "owner", password: process.env.PF_DEV_OWNER_PASSWORD ?? "" };
const VIEWER = { username: "viewer", password: process.env.PF_DEV_VIEWER_PASSWORD ?? "" };

async function signIn(page: Page, user: { username: string; password: string }): Promise<void> {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByRole("link", { name: "Sign in" }).click();

  // Keycloak's login form.
  await page.locator("#username").fill(user.username);
  await page.locator("#password").fill(user.password);
  await page.locator("#kc-login").click();

  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
}

test.beforeAll(() => {
  expect(OWNER.password, "PF_DEV_OWNER_PASSWORD must be set (it is defined in .env)").not.toBe("");
  expect(VIEWER.password, "PF_DEV_VIEWER_PASSWORD must be set (it is defined in .env)").not.toBe("");
});

test("visitors who are not signed in are sent to the sign-in page", async ({ page }) => {
  await page.goto("/settings");

  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("the overview shows live platform status after signing in", async ({ page }) => {
  await signIn(page, OWNER);

  await expect(page.getByText("All components operational")).toBeVisible();
  for (const name of ["pf-gateway", "core", "postgres", "ai", "identity-provider"]) {
    await expect(page.getByTestId(`component-${name}`)).toContainText("Operational");
  }
});

test("the session cookie is HttpOnly and no token reaches the browser", async ({ page, context }) => {
  await signIn(page, OWNER);

  const cookies = await context.cookies("http://localhost:3000");
  const session = cookies.find((cookie) => cookie.name.endsWith("pf_sid"));
  expect(session, "session cookie").toBeDefined();
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Strict");

  // An access token is a JWT; none may be visible to scripts or stored cookies.
  expect(await page.evaluate(() => document.cookie)).not.toContain("pf_sid");
  for (const cookie of cookies) {
    expect(cookie.value).not.toMatch(/^eyJ/);
  }
  const stored = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
  expect(stored).not.toContain("eyJ");
});

test("every section is reachable and unbuilt sections say so", async ({ page }) => {
  await signIn(page, OWNER);
  const nav = page.getByRole("navigation", { name: "Sections" });

  const sections = [
    { label: "Cloud", path: "/cloud", implemented: false },
    { label: "VPN", path: "/vpn", implemented: false },
    { label: "Network Monitoring", path: "/network", implemented: false },
    { label: "Security Lab", path: "/lab", implemented: false },
    { label: "AI Investigator", path: "/ai", implemented: false },
    { label: "Settings", path: "/settings", implemented: true },
    { label: "Overview", path: "/", implemented: true },
  ];
  for (const section of sections) {
    await nav.getByRole("link", { name: section.label }).click();

    await expect(page).toHaveURL(new RegExp(`${section.path}$`));
    await expect(page.getByRole("heading", { level: 1, name: section.label })).toBeVisible();
    await expect(page.getByTestId("not-implemented")).toHaveCount(section.implemented ? 0 : 1);
  }
});

test("the AI Investigator page reports the service's capabilities as not implemented", async ({ page }) => {
  await signIn(page, OWNER);
  await page.goto("/ai");

  await expect(page.getByText("pf-aid")).toBeVisible();
  await expect(page.getByText("investigations", { exact: true })).toBeVisible();
  await expect(page.getByText("Not implemented", { exact: true })).toHaveCount(3);
});

test("an owner can create and delete a project in settings", async ({ page }) => {
  await signIn(page, OWNER);
  await page.goto("/settings");

  await expect(page.getByTestId("roles")).toContainText("owner");

  const slug = `e2e-${Date.now().toString(36)}`;
  await page.getByLabel("Slug").fill(slug);
  await page.getByLabel("Name").fill("End-to-end test");
  await page.getByRole("button", { name: "Create project" }).click();

  const projects = page.getByRole("list", { name: "Projects" });
  await expect(projects.getByText(slug)).toBeVisible();

  // The same slug is rejected by the API and the reason is shown.
  await page.getByLabel("Slug").fill(slug);
  await page.getByLabel("Name").fill("Duplicate");
  await page.getByRole("button", { name: "Create project" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "already exists" })).toBeVisible();

  await page.getByRole("button", { name: `Delete project ${slug}` }).click();
  await expect(page.getByText(slug)).toHaveCount(0);
});

test("a viewer can see projects but is not offered write actions", async ({ page }) => {
  await signIn(page, VIEWER);
  await page.goto("/settings");

  await expect(page.getByTestId("roles")).toContainText("viewer");
  await expect(page.getByText("cannot create or delete")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create project" })).toHaveCount(0);

  // The API enforces the same rule, whatever the page offers.
  const response = await page.request.post("/bff/api/core/projects", {
    headers: { origin: "http://localhost:3000" },
    data: { slug: "viewer-attempt", name: "Viewer attempt" },
  });
  expect(response.status()).toBe(403);
});

test("signing out ends the session", async ({ page }) => {
  await signIn(page, OWNER);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);

  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
});
