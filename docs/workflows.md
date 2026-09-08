# Automate user lifecycle tasks

Workflows let realm administrators apply a sequence of actions when a user event occurs, on a schedule, or when an administrator starts the workflow for one user. Every execution is recorded so delayed, failed, and completed work can be reviewed.

Open **Workflows** in the administration console and select a realm.

## Create a workflow

Enter a name and optional description. An enabled workflow can use any combination of these triggers:

- **Events** start the workflow when a matching user event is recorded. Enter exact names such as `user.created`, `user.authenticated`, `user.role_assigned`, or `user.account_recovery_completed`. Use `user.*` to match every user event.
- **Run on a schedule** checks eligible users at the selected interval. **Users per run** limits each batch. Users that have waited longest are considered first.
- **Run now** starts an enabled workflow for the user selected below the workflow list.

A workflow with no event or schedule remains available for manual use.

![Workflow editor with event and schedule triggers](assets/workflows/workflow-editor.png)

## Select users with conditions

Add conditions when the actions should apply only to some users. All configured conditions must match. You can check:

- whether the account is enabled;
- whether the email address is verified;
- whether a user attribute has a particular value;
- how many days the user has been inactive;
- whether the user has a role;
- whether the user belongs to a group.

Leave the conditions empty to apply the workflow to every user reached by its trigger.

## Build the action sequence

Actions run from top to bottom. Use the arrow buttons to change their order. Each action can run immediately or wait for a number of seconds before it begins.

Available actions are:

- enable, disable, or delete the user;
- add or remove a required action, including password update, email verification, profile update, MFA configuration, and terms acceptance;
- sign the user out by revoking active sessions;
- set or remove a user attribute;
- grant or revoke a role;
- add the user to a group or remove the user from a group.

A common credential review workflow adds **Update password** and then signs the user out. The user must choose a new password at the next sign-in.

Choose **Create workflow**. The configured workflow appears below the editor and can be edited, disabled, or deleted.

![Configured credential review workflow](assets/workflows/workflow-list.png)

## Process scheduled and delayed actions

Choose **Process due actions** to start scheduled batches and continue actions whose waiting period has ended. Configure your deployment scheduler to invoke the same operation regularly when you rely on schedules or delayed actions.

Event actions without a delay run as soon as the matching event is recorded. Manual actions without a delay run when you choose **Run now**.

## Review execution history

Open **Execution history** to see the workflow, user, trigger, progress, start time, and current status for each run.

- **Completed** means every action succeeded.
- **Waiting** means the next action has a configured delay.
- **Failed** includes the error that stopped the action. Correct the cause and choose **Retry** to continue from that action.
- **Cancelled** means an administrator stopped the execution or deleted its workflow.

Queued, waiting, and failed executions can be cancelled. Completed actions are not undone.

![Workflow execution history showing a completed manual run](assets/workflows/execution-history.png)

Workflow definitions are included in realm exports. Execution history is operational data and is not copied to another realm.

Delegated administrators need `workflows:read` to view workflows and history, `workflows:write` to create or change definitions, and `workflows:execute` to start, retry, cancel, or process executions.
