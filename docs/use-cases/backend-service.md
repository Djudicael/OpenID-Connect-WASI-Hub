# Use case: connect a backend service

[Documentation home](../README.md) · [Service accounts and agents](../service-accounts-and-agents.md) · [Protect APIs](../authorization-services.md)

Use this journey for a scheduled job, API integration, or backend workload that calls another service without a signed-in person.

## Outcome

The workload receives a short-lived access token through Client Credentials, and the receiving API validates the workload identity, audience, and scopes.

## A. Define the API contract

Choose the API audience and scopes before creating the client, for example audience `orders-api` with scopes `orders.read` and `orders.write`. Give each permission one clear business meaning.

## B. Create the workload client

1. Open **Clients** and add a confidential client such as `billing-worker`.
2. Enable Client Credentials.
3. Allow only the workload scopes.
4. Generate the secret and save it immediately in the workload secret manager.
5. Add an audience protocol mapper when the API checks a dedicated audience.

![Confidential client configured for Client Credentials](../assets/application-integration/service-client.png)

## C. Obtain and cache tokens

Call the realm token endpoint with the client ID and secret. Cache the returned token until shortly before its 15-minute expiry, then obtain a new one. Do not call the token endpoint for every business request.

## D. Validate at the API

The receiving API loads the realm signing keys and validates signature, issuer, audience, expiry, and required scopes. It should identify the caller from the client subject rather than expecting a user profile.

## E. Operate the credential

Monitor authentication failures and disable the client when the workload is retired. To replace a credential, create a replacement client, switch the workload, verify it, and then disable the old client. Use separate clients for production, staging, and unrelated jobs.

## Completion check

- The workload can obtain a token with its allowed scopes.
- A request for an unapproved scope is rejected or omitted.
- UserInfo rejects the machine token, as expected.
- The API rejects wrong issuer, audience, expiry, and missing scope.
- Disabling the client prevents new tokens.
- Credential replacement and rollback procedures are documented.
