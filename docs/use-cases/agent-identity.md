# Use case: choose an identity for an agent

[Documentation home](../README.md) · [Service accounts and agents](../service-accounts-and-agents.md) · [API keys](../api-keys.md)

Use this journey for an automation agent, AI agent, build worker, or integration process. Start by deciding whose authority the agent should use.

## Outcome

Independent, user-delegated, and administrative actions use separate credentials with precise scopes, audiences, storage, and revocation paths.

## A. Classify each action

| Agent action | Credential |
|---|---|
| Calls a business API as itself | Confidential client and Client Credentials token |
| Acts for a currently signed-in person | Authorization Code with PKCE user token |
| Continues person-approved work later | User-approved offline grant |
| Requests approval on another device | CIBA request and resulting user token |
| Administers hub users or configuration | Realm API key with explicit administration permissions |

An agent that performs several categories should hold separate credentials for them.

## B. Create an independent agent identity

1. Create a confidential OIDC client for the agent and environment.
2. Enable Client Credentials and select only its business API scopes.
3. Add the API audience claim expected by the receiving service.
4. Store the generated secret in the agent runtime's secret manager.
5. Request short-lived tokens and cache them until near expiry.

![Confidential client configured for an independent agent](../assets/application-integration/service-client.png)

Create separate clients for agents with different owners, permissions, or revocation needs.

## C. Add user delegation when required

Use an interactive flow when the action affects a person's data or relies on their permission. Show the requested scope and obtain consent. Use `offline_access` only when the user expects the agent to continue later, and provide a way to revoke the grant from **My Account**.

CIBA is useful when the agent begins the request on one channel and the person approves from an existing account session on another device.

## D. Add administrative automation when required

If the agent provisions users, manages organization membership, or runs workflow timers, create a separate API key in **API Keys**. Grant only the exact administrative actions. For example, a timer needs `workflows:execute`; it does not need `admin`.

## E. Enforce policy at the receiving service

Validate issuer, signature, audience, expiry, and scopes. Also check whether the subject is a client or user before allowing an action that requires a person. Use Authorization Services when the decision depends on resources, ownership, groups, attributes, or time.

## F. Record and revoke

Give the agent a recognizable client and API-key name. Correlate its requests through audit events and request IDs. Disable the OIDC client to stop new business API tokens; revoke the API key to stop hub administration. Revoke user consent or offline grants independently.

## Completion check

- Machine and user-delegated actions use different tokens.
- The agent holds no human password.
- Every secret is stored outside source code and browser storage.
- Each receiving API validates audience and scope.
- The operator can revoke one agent without interrupting unrelated workloads.
- Administrative access uses a separate least-privilege API key.
