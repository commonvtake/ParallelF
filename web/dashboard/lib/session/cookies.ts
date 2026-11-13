// Cookie names and attributes.

export interface CookieOptions {
  httpOnly: true;
  secure: boolean;
  sameSite: "strict" | "lax";
  path: "/";
  maxAge?: number;
}

/**
 * Session cookie name. With HTTPS the `__Host-` prefix makes browsers
 * refuse the cookie unless it is Secure, host-only and scoped to "/".
 */
export function sessionCookieName(secure: boolean): string {
  return secure ? "__Host-pf_sid" : "pf_sid";
}

/** Binds an in-progress login to the browser that started it. */
export function loginCookieName(secure: boolean): string {
  return secure ? "__Host-pf_login" : "pf_login";
}

/**
 * SameSite=Strict: the session cookie is never sent on requests initiated
 * by another site, which removes cross-site request forgery as a class.
 */
export function sessionCookieOptions(secure: boolean, maxAgeSeconds: number): CookieOptions {
  return { httpOnly: true, secure, sameSite: "strict", path: "/", maxAge: maxAgeSeconds };
}

/**
 * SameSite=Lax: this cookie must survive the top-level redirect back from
 * the identity provider, which a Strict cookie would not.
 */
export function loginCookieOptions(secure: boolean): CookieOptions {
  return { httpOnly: true, secure, sameSite: "lax", path: "/", maxAge: 600 };
}
