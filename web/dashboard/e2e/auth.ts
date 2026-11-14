// Signing in through the real identity provider with the development users
// defined in deploy/keycloak/realm/parallelf-realm.json.

import { expect, type Page } from "@playwright/test";

export interface User {
  username: string;
  password: string;
}

export const OWNER: User = { username: "owner", password: process.env.PF_DEV_OWNER_PASSWORD ?? "" };
export const VIEWER: User = { username: "viewer", password: process.env.PF_DEV_VIEWER_PASSWORD ?? "" };

export async function signIn(page: Page, user: User): Promise<void> {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByRole("link", { name: "Sign in" }).click();

  // Keycloak's login form.
  await page.locator("#username").fill(user.username);
  await page.locator("#password").fill(user.password);
  await page.locator("#kc-login").click();

  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
}
