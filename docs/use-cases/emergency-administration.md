# Use case: set up delegated and emergency administration

[Documentation home](../README.md) · [Delegated administration](../delegated-administration.md) · [API keys](../api-keys.md)

Use this journey to give routine operators limited access while retaining a controlled way to recover from an administrator lockout.

## Outcome

Helpdesk, audit, organization, and automation duties use separate permissions, while a protected full administrator account is available for exceptional recovery.

## A. Separate routine duties

1. Create roles for each operator function, such as helpdesk, security audit, application administration, or workflow operation.
2. Add only the exact read and write permissions from the delegated administration reference.
3. Assign roles through groups where possible.
4. For a customer administrator, restrict organization permissions to that organization's UUID.
5. Use realm API keys for automation rather than a human administrator password.

![Delegated role with explicit administration permissions](../assets/delegated-administration/create-role.png)

## B. Prepare emergency access

Create a dedicated full administrator account with a strong unique password, MFA, recovery codes, and no routine use. Store its credentials and recovery material in the organization's controlled emergency-access system. Define who may retrieve them, under what conditions, and how use is reviewed.

The platform does not apply a special bypass to this account. It remains subject to normal password, MFA, session, and audit behavior.

## C. Test boundaries and recovery

Use test operators to confirm allowed actions and forbidden access to other realms or organizations. Exercise the emergency account, verify its audit events, then revoke its sessions. Test recovery while ordinary identity-provider or directory login is unavailable.

## D. Review periodically

Review role membership, API-key last use and expiry, emergency credential custody, recovery codes, and audit events. Remove departing operators from their groups and revoke sessions immediately.

## Completion check

- Routine administrators cannot perform unrelated sensitive actions.
- Organization administrators cannot cross tenant boundaries.
- Emergency access works without relying on the failed external provider.
- Every emergency use creates an incident or review record.

