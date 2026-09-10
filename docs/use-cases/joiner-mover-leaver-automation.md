# Use case: automate joiner, mover, and leaver processes

[Documentation home](../README.md) · [Workflows](../workflows.md) · [Workforce lifecycle](workforce-user-lifecycle.md)

Use this journey to apply repeatable access changes when a person joins, changes responsibility, becomes inactive, or leaves.

## Outcome

Enabled workflows assign onboarding actions, update access, and disable departing users with durable execution history and an operator-controlled scheduler.

## A. Define authoritative events

Decide whether users originate locally, from a directory, or through an identity provider. List the exact events or user attributes that mark a joiner, mover, and leaver. Keep the directory and workflow responsibilities separate so they do not repeatedly overwrite each other.

## B. Build onboarding

Create an event workflow for `user.created` that adds required actions such as password update, email verification, profile completion, MFA configuration, or terms acceptance. Add the standard group or role only when every new user should receive it.

## C. Build access changes

Use exact lifecycle events for immediate changes or a scheduled workflow with attribute, role, or group conditions. Add and remove roles or groups in a clear order. Revoke sessions after reducing access when the change must take effect before current tokens expire.

## D. Build offboarding

Create a workflow that disables the user first, revokes sessions, removes roles and groups, and deletes the account only when retention policy allows. Test managed organization users separately because removing their membership can delete the managed account.

![Workflow editor with event and scheduled triggers](../assets/workflows/workflow-editor.png)

## E. Operate the scheduler

Create a realm API key containing only `workflows:execute`. Configure the deployment scheduler to call the realm's `workflows/run-due` operation regularly. Review **Execution history**, retry corrected failures, and cancel work that should no longer proceed.

## Completion check

- Each trigger has an owner and an authoritative source.
- Access removal includes session revocation where required.
- Scheduled and delayed actions run without manual intervention.
- Pilot users pass joiner, mover, leaver, retry, and cancellation tests.

