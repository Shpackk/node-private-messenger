export const migrations = [
	`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
	`CREATE TABLE IF NOT EXISTS accounts (
    account_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username text NOT NULL UNIQUE,
    display_name text,
    password_verifier text NOT NULL,
    discoverable boolean NOT NULL DEFAULT true,
    token_version integer NOT NULL DEFAULT 1,
    deleted_at timestamptz,
    duress_verifier text,
    mfa_secret_ciphertext text,
    mfa_secret_iv text,
    mfa_secret_salt text,
    mfa_enabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
	"ALTER TABLE accounts ADD COLUMN IF NOT EXISTS mfa_secret_ciphertext text",
	"ALTER TABLE accounts ADD COLUMN IF NOT EXISTS mfa_secret_iv text",
	"ALTER TABLE accounts ADD COLUMN IF NOT EXISTS mfa_secret_salt text",
	"ALTER TABLE accounts ADD COLUMN IF NOT EXISTS mfa_enabled_at timestamptz",
	`CREATE TABLE IF NOT EXISTS username_reservations (
    username text PRIMARY KEY,
    reserved_until timestamptz NOT NULL
  )`,
	`CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash text PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
	`CREATE TABLE IF NOT EXISTS prekeys (
    account_id uuid PRIMARY KEY REFERENCES accounts(account_id),
    identity_key text NOT NULL,
    signed_pre_key text NOT NULL,
    signed_pre_key_signature text NOT NULL,
    one_time_pre_keys text[] NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now()
  )`,
	`CREATE TABLE IF NOT EXISTS blocks (
    blocker_account_id uuid NOT NULL REFERENCES accounts(account_id),
    blockee_account_id uuid NOT NULL REFERENCES accounts(account_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_account_id, blockee_account_id)
  )`,
	`CREATE TABLE IF NOT EXISTS push_tokens (
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    platform text NOT NULL,
    token text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, platform, token)
  )`,
	`CREATE TABLE IF NOT EXISTS envelopes (
    envelope_id uuid PRIMARY KEY,
    recipient_account_id uuid NOT NULL REFERENCES accounts(account_id),
    sender_account_id uuid NOT NULL REFERENCES accounts(account_id),
    client_message_id uuid NOT NULL,
    ciphertext text NOT NULL,
    signature text NOT NULL,
    byte_size integer NOT NULL,
    expires_at timestamptz NOT NULL,
    lease_id uuid,
    leased_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
	"CREATE INDEX IF NOT EXISTS envelopes_recipient_pending_idx ON envelopes(recipient_account_id, expires_at)",
	`CREATE TABLE IF NOT EXISTS queue_counters (
    recipient_account_id uuid PRIMARY KEY REFERENCES accounts(account_id),
    envelope_count integer NOT NULL DEFAULT 0,
    byte_count integer NOT NULL DEFAULT 0
  )`,
	`CREATE TABLE IF NOT EXISTS push_wakeups (
    id bigserial PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
];
