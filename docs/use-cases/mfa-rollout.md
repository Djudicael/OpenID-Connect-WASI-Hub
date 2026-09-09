# Use case: roll out MFA and passkeys safely

[Documentation home](../README.md) · [Multi-factor authentication](../multi-factor-authentication.md) · [Authentication flows](../authentication-flows.md)

Use this journey to introduce authenticator apps, passkeys, recovery codes, and step-up authentication without locking out the user population.

## Outcome

Users enroll a supported second factor, retain a tested recovery path, and sensitive applications can require recent MFA.

## A. Define the policy

Decide which populations need MFA, which applications or scopes need step-up, the accepted methods, and how support verifies identity before resetting MFA. Start with administrators and a pilot group.

## B. Prepare enrollment and recovery

1. Confirm **My Account** is reachable.
2. Ensure users can register an authenticator app or passkey under **Sign-in Security**.
3. Require users to download the one-time recovery codes created during enrollment.
4. Train support on **Users → Multi-factor authentication → Reset MFA**.
5. Test the recovery process before making enrollment mandatory.

![Account security settings for MFA enrollment](../assets/multi-factor-authentication/security-settings.png)

## C. Enforce gradually

Assign **Configure MFA** to pilot users or enable realm-wide MFA enrollment in the authentication flow. For sensitive clients or scopes, enable step-up and configure a maximum authentication age. Expand only after successful enrollment, challenge, and recovery measurements.

## D. Exercise every path

Test TOTP with correct and incorrect device time, multiple passkeys, one-time recovery-code use, replacing recovery codes, removing a method after recent MFA, five failed challenges, challenge expiry, and administrator reset. Confirm reset signs the user out everywhere.

## Completion check

- Every required user has at least one enrolled method and stored recovery codes.
- Step-up triggers only for the intended clients or scopes.
- Lost-device recovery and administrator identity verification are documented.
- A user cannot reuse a recovery or authenticator code.

