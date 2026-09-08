use oidc_core::{
    OidcError,
    models::{
        Client, ClientPolicyEvaluation, ClientRegistrationContext, enforce_client_policies,
        evaluate_client_policies,
    },
};
use oidc_repository::{Connection, repositories::client_policy_repo::ClientPolicyRepo};

pub async fn evaluate(
    conn: &mut Connection,
    client: &Client,
    context: ClientRegistrationContext,
) -> Result<ClientPolicyEvaluation, OidcError> {
    let profiles = ClientPolicyRepo
        .list_profiles(conn, client.realm_id)
        .await?;
    let policies = ClientPolicyRepo
        .list_policies(conn, client.realm_id)
        .await?;
    Ok(evaluate_client_policies(
        client, context, &policies, &profiles,
    ))
}

pub async fn enforce(
    conn: &mut Connection,
    client: &Client,
    context: ClientRegistrationContext,
) -> Result<ClientPolicyEvaluation, OidcError> {
    let profiles = ClientPolicyRepo
        .list_profiles(conn, client.realm_id)
        .await?;
    let policies = ClientPolicyRepo
        .list_policies(conn, client.realm_id)
        .await?;
    enforce_client_policies(client, context, &policies, &profiles)
}
