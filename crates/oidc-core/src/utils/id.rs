use uuid::Uuid;

/// Generate a new UUID v7 (time-sortable).
pub fn generate_uuid_v7() -> Uuid {
    Uuid::now_v7()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_v7_is_sortable() {
        let id1 = generate_uuid_v7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = generate_uuid_v7();
        assert!(id1 < id2);
    }
}
