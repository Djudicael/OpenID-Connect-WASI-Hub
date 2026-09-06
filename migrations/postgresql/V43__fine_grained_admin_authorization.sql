-- Preserve the access existing users had before management authorization was
-- moved from an implicit token scope to explicit role permissions.
INSERT INTO roles (id, realm_id, name, description, permissions, created_at, updated_at)
SELECT gen_random_uuid(), r.id, 'realm-admin', 'Full realm administrator', '["admin"]'::jsonb, NOW(), NOW()
FROM realms r
WHERE r.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM roles role
      WHERE role.realm_id = r.id
        AND role.name = 'realm-admin'
        AND role.deleted_at IS NULL
  );

UPDATE roles
SET permissions = CASE
        WHEN permissions ? 'admin' THEN permissions
        ELSE permissions || '["admin"]'::jsonb
    END,
    updated_at = NOW()
WHERE name = 'realm-admin'
  AND deleted_at IS NULL;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, role.id
FROM users u
JOIN roles role
  ON role.realm_id = u.realm_id
 AND role.name = 'realm-admin'
 AND role.deleted_at IS NULL
WHERE u.deleted_at IS NULL
ON CONFLICT DO NOTHING;
