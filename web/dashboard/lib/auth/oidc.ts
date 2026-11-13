// OpenID Connect client (authorization code flow with PKCE) built on the
// certified `openid-client` library. The dashboard server is a confidential
// client: the browser never sees tokens or the client secret.

import * as client from "openid-client";

import { getConfig } from "@/lib/config";
import type { PendingLogin, SessionUser } from "@/lib/session/store";

export interface TokenSet {
  accessToken: string;
  accessTokenExpiresAt: number;
  refreshToken?: string;
  idToken?: string;
}

export interface LoginResult extends TokenSet {
  user: SessionUser;
}

const SCOPES = "openid profile email";
const DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS = 60;

let configurationPromise: Promise<client.Configuration> | undefined;

async function loadConfiguration(): Promise<client.Configuration> {
  const { oidc } = getConfig();

  // The discovery document is fetched over the internal network, where the
  // provider's hostname differs from the browser-facing issuer. The issuer
  // it reports must still be exactly the one we expect.
  const response = await fetch(oidc.discoveryUrl, { cache: "no-store", signal: AbortSignal.timeout(5000) });
  if (!response.ok) {
    throw new Error(`identity provider discovery returned HTTP ${response.status}`);
  }
  const metadata = (await response.json()) as client.ServerMetadata;
  if (metadata.issuer !== oidc.issuer) {
    throw new Error(
      `identity provider issuer mismatch: expected ${oidc.issuer}, got ${String(metadata.issuer)}`,
    );
  }

  const configuration = new client.Configuration(metadata, oidc.clientId, oidc.clientSecret);
  if (new URL(oidc.discoveryUrl).protocol === "http:") {
    // Local development talks to the provider over plain HTTP inside the
    // container network. Production deployments use HTTPS URLs.
    client.allowInsecureRequests(configuration);
  }
  return configuration;
}

/** Returns the provider configuration, discovering it on first use. */
function getConfiguration(): Promise<client.Configuration> {
  configurationPromise ??= loadConfiguration().catch((error: unknown) => {
    configurationPromise = undefined; // retry on the next request
    throw error;
  });
  return configurationPromise;
}

function redirectUri(): string {
  return `${getConfig().publicUrl}/auth/callback`;
}

function toTokenSet(tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers): TokenSet {
  const lifetime = tokens.expiresIn() ?? DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS;
  return {
    accessToken: tokens.access_token,
    accessTokenExpiresAt: Date.now() + lifetime * 1000,
    refreshToken: tokens.refresh_token,
    idToken: tokens.id_token,
  };
}

/** Creates the PKCE verifier, state and nonce and the provider login URL. */
export async function beginLogin(
  returnTo: string,
): Promise<{ url: URL; pending: Omit<PendingLogin, "expiresAt"> }> {
  const configuration = await getConfiguration();

  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();

  const url = client.buildAuthorizationUrl(configuration, {
    redirect_uri: redirectUri(),
    scope: SCOPES,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return { url, pending: { state, codeVerifier, nonce, returnTo } };
}

/**
 * Exchanges the authorization code for tokens. `search` is the query string
 * of the callback request. The library validates state, nonce, issuer,
 * audience and expiry of the ID token.
 */
export async function completeLogin(search: string, pending: PendingLogin): Promise<LoginResult> {
  const configuration = await getConfiguration();

  const callbackUrl = new URL(redirectUri());
  callbackUrl.search = search;

  const tokens = await client.authorizationCodeGrant(configuration, callbackUrl, {
    pkceCodeVerifier: pending.codeVerifier,
    expectedState: pending.state,
    expectedNonce: pending.nonce,
    idTokenExpected: true,
  });

  const claims = tokens.claims();
  if (!claims?.sub) {
    throw new Error("identity provider returned no subject");
  }
  const text = (value: unknown): string | undefined =>
    typeof value === "string" && value.length > 0 ? value : undefined;

  return {
    ...toTokenSet(tokens),
    user: {
      subject: claims.sub,
      username: text(claims.preferred_username) ?? claims.sub,
      name: text(claims.name),
      email: text(claims.email),
    },
  };
}

/** Obtains a new access token with the session's refresh token. */
export async function refreshTokens(refreshToken: string): Promise<TokenSet> {
  const configuration = await getConfiguration();
  return toTokenSet(await client.refreshTokenGrant(configuration, refreshToken));
}

/** URL that ends the provider's single sign-on session, then returns to /login. */
export async function endSessionUrl(idToken: string): Promise<URL> {
  const configuration = await getConfiguration();
  return client.buildEndSessionUrl(configuration, {
    id_token_hint: idToken,
    post_logout_redirect_uri: `${getConfig().publicUrl}/login`,
  });
}
