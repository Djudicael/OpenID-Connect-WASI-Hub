use axum::{extract::Query, response::Redirect};
use std::collections::HashMap;

/// Authorization endpoint handler.
pub async fn authorize_handler(Query(params): Query<HashMap<String, String>>) -> Redirect {
    let _ = params;
    // TODO: implement authorization flow
    Redirect::temporary("/login")
}
