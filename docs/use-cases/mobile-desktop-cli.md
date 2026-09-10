# Use case: connect mobile, desktop, and command-line applications

[Documentation home](../README.md) · [Application integration](../application-integration.md) · [Offline access](../offline-access.md)

Use this journey for applications that cannot safely keep a client secret.

## Outcome

Mobile and desktop applications use Authorization Code with S256 PKCE, while input-constrained tools can use Device Authorization without collecting the user's password.

## A. Register a public client

1. Open **Clients** and create a **Public** client.
2. For mobile or desktop use, enable **Authorization Code** and **Refresh Token**, keep PKCE required, and register the exact callback URI.
3. For a terminal or constrained device, enable **Device Code**.
4. Allow only the scopes the application needs.

Do not embed a confidential-client secret in an application package or executable.

## B. Use Authorization Code with PKCE

Generate a fresh verifier, S256 challenge, state, and nonce for each sign-in. Open authorization in the system browser, accept only the registered callback, verify state, and exchange the code with the original verifier. Validate issuer, signature, audience, nonce, and expiry.

## C. Use Device Authorization

Call the device authorization endpoint discovered from the realm metadata. Show the returned verification address and user code, then poll the token endpoint no faster than the returned interval. Handle `authorization_pending`, `slow_down`, denial, and expiry. Never ask the user to type their hub password into the CLI.

Device Authorization cannot issue offline access. Use an interactive Authorization Code flow when the application needs a user-approved offline grant.

## D. Test lifecycle behavior

Test cancelled browser sign-in, wrong state, reused code, an expired device code, polling too quickly, consent denial, token expiry, session revocation, and logout. Clear local tokens when refresh or revocation indicates that access ended.

## Completion check

- Every installed application is a public client with no embedded secret.
- PKCE, state, nonce, and token validation are enforced.
- Device flow never handles the user's password.
- Revocation and local token deletion have been tested.

