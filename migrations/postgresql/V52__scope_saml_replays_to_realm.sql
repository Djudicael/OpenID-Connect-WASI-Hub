-- SAML identifiers are unique within an issuer. Scope replay detection to each realm.
ALTER TABLE saml_assertion_replays DROP CONSTRAINT saml_assertion_replays_pkey;
ALTER TABLE saml_assertion_replays ADD PRIMARY KEY (realm_id, assertion_id);
