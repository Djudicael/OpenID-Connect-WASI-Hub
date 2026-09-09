# Configure passwords and account recovery

[Documentation home](README.md) · [User management](user-management.md) · [Email delivery](email-delivery.md)

Password policy applies per realm. Users can change a known password from **My Account** and use a time-limited email link when they forget it.

## Set the password policy

1. Open **Password Policies**.
2. Select the realm.
3. Configure minimum and maximum length, required uppercase, lowercase, digit, and special characters, minimum unique characters, and maximum repeated identical characters.
4. Add blocked passwords one per line.
5. Save the policy.

Test the final policy with representative passwords before onboarding users. Communicate requirements before the user submits a change.

## Give a new user an initial password

Create the user with a strong initial password, then add **Update password** under the user's **Required actions**. Share the initial credential through an approved secure channel and never through the same message as the account identifier when policy forbids it.

At first sign-in, token issuance remains blocked until the user chooses a password that passes the realm policy.

## Change a known password

The user opens **My Account**, selects **Password**, enters the current and new passwords, and submits the change. A successful change revokes the user's other sessions while keeping the current account-console session.

Accounts that authenticate only through an external identity provider may not have a local password.

## Recover a forgotten password

Configure [transactional email](email-delivery.md), then let the user request a password reset for their realm account. The reset link is single-use and expires after 15 minutes. The request response does not reveal whether an email address exists, reducing account discovery.

After a successful reset, the used link cannot be submitted again. If it expires, request another message.

## Verify an email address

An email-verification link is single-use and expires after 24 hours. Changing an account email marks the new address unverified. Assign **Verify email** when verification is required before token issuance.

## Recover MFA access

Recovery codes and passkeys are covered in [multi-factor authentication](multi-factor-authentication.md). When the user has no remaining method, an authorized administrator can use **Reset MFA** on the user details page. This removes MFA credentials and revokes sessions so the user must authenticate and enroll again.

