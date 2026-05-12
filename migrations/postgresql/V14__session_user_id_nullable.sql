-- V14__session_user_id_nullable.sql
-- Allow sessions with no end-user (client_credentials grant).

ALTER TABLE sessions ALTER COLUMN user_id DROP NOT NULL;
