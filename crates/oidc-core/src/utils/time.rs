/// Time formatting utilities.
pub fn format_timestamp(seconds: u64) -> String {
    let dt = chrono::DateTime::from_timestamp(seconds as i64, 0).unwrap_or_default();
    dt.to_rfc3339()
}
