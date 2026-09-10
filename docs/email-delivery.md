# Configure transactional email delivery

[Documentation home](README.md) · [Email templates](realm-themes-localization-email.md) · [Organizations](organizations.md)

Email delivery is used for password reset, email verification, and organization invitations. The runtime sends through a Resend-compatible HTTPS API.

## Prepare the sender

1. Create an account with your Resend-compatible email provider.
2. Verify the sending domain and sender address with that provider.
3. Create an API key limited to sending email when the provider supports restricted keys.
4. Store the API key in the deployment secret manager.

## Configure the runtime

Set these variables on the hub runtime:

| Variable | Purpose |
|---|---|
| `OIDC_RESEND_API_KEY` | Provider API key used to send messages |
| `OIDC_EMAIL_FROM` | Verified sender address shown to recipients |
| `OIDC_RESEND_ENDPOINT` | Optional compatible API endpoint; defaults to `https://api.resend.com/emails` |

Both `OIDC_RESEND_API_KEY` and `OIDC_EMAIL_FROM` are required to enable delivery. Restart or redeploy the runtime after changing them.

Do not put the provider API key in realm settings, an email template, a client secret, or the administration console.

## Customize messages

Open **Realms**, select the realm, and edit its email templates. Password reset, verification, and organization invitation templates each support HTML and plain text. Add locale-specific variants when the realm supports more than one language.

Use the preview before saving. The [theme and template guide](realm-themes-localization-email.md#customize-an-email-template) lists supported placeholders and locale fallback.

## Verify delivery

Test every enabled journey with non-production accounts:

1. Request a password reset and open the one-time link.
2. Assign **Verify email** to a user and complete verification.
3. Create an organization invitation and accept it.
4. Confirm the correct sender, realm branding, language, destination, and action URL.
5. Confirm expired or already-used links are rejected.

## Troubleshooting

- **No message arrives:** confirm both required environment variables are present on the running instance and inspect runtime logs for the provider response.
- **The provider rejects the sender:** verify `OIDC_EMAIL_FROM` with the provider and check its domain policy.
- **Development reports success but no email arrives:** without complete provider configuration, the runtime uses its development sender and does not deliver messages.
- **Links use the wrong host:** correct the public issuer and proxy configuration so generated URLs use the externally reachable identity address.
- **Only one language is wrong:** preview that template locale and confirm the realm's supported and default locale settings.

