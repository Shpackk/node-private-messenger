# Backend Protocol Contract

## Encoding

HTTP and WebSocket application frames use UTF-8 JSON. Binary values use unpadded base64url.
Identifiers use UUIDs. Unknown fields are rejected. Current protocol version is `1`.

Ciphertext is opaque. Backend does not accept plaintext or encrypted event-type metadata outside
ciphertext.

## Public-Key Formats

Device authentication and identity public keys use DER-encoded Ed25519 SubjectPublicKeyInfo,
then unpadded base64url.

Signed prekey signature input:

```text
messenger-signed-prekey-v1
<signedPreKey>
```

Authentication challenge signature input:

```text
messenger-auth-v1
<challengeId>
<nonce>
<expiresAt>
```

Envelope signature input:

```text
<version>
<envelopeId>
<recipientAccountId>
<createdAt>
<ttlSeconds>
<ciphertext>
```

Every line ends only between fields; no trailing newline. Clients must sign exact UTF-8 bytes.

## Authentication

1. Create account with username and public key bundle.
2. Request challenge by exact username.
3. Sign canonical challenge using registered device authentication key.
4. Exchange signature for 10-minute access token and 30-day refresh token.
5. Sign `messenger-refresh-v1\n<refreshToken>` with device authentication key.
6. Refresh atomically rotates account token version; previous access and refresh tokens become
   invalid.

One registered device key exists per account. Reinstall or key loss makes account inaccessible.
WebSocket authentication sends access token as `bearer.<token>` in
`Sec-WebSocket-Protocol`; never put token in URL.

## HTTP Endpoints

- `POST /v1/accounts`: register unique username and initial public key bundle.
- `POST /v1/auth/challenges`: create single-use two-minute challenge.
- `POST /v1/auth/verify`: verify device signature and issue tokens.
- `POST /v1/auth/refresh`: rotate refresh/access tokens.
- `GET /v1/usernames/:username/available`: check uniqueness and cooldown.
- `PUT|DELETE /v1/discovery`: enable or disable exact-match discovery.
- `GET /v1/discovery/:username`: atomically consume one prekey for discoverable account.
- `POST /v1/keys`: update signed prekey and replenish one-time prekeys.
- `GET /v1/keys/:accountId`: atomically consume contact prekey unless blocked.
- `PUT /v1/blocks`: block account.
- `DELETE /v1/blocks/:accountId`: remove block without restoring trust.
- `PUT /v1/push-token`: register APNs or FCM token.
- `POST /v1/envelopes`: submit signed ciphertext.
- `GET /v1/envelopes`: lease up to 100 pending envelopes.
- `POST /v1/envelopes/ack`: permanently delete durably saved envelopes.
- `DELETE /v1/account`: authenticated permanent deletion.
- `POST /v1/account/duress-delete`: generic-response permanent deletion using one-time configured
  secret.

All authenticated endpoints use `Authorization: Bearer <access-token>`.

## Envelope Behavior

Backend stores accepted envelopes before attempting live delivery. Recipient acknowledgment deletes
matching envelope idempotently. Failed live delivery sends generic content-free push wake-up.

TTL starts at server acceptance, not client `createdAt`. DynamoDB TTL is cleanup only; fetch path
also rejects expired records. Queue caps never evict accepted messages.

Block checks run before queue write and again inside DynamoDB transaction. Blocked, missing, and
queue-full recipients use same `RECIPIENT_UNAVAILABLE` response.

## WebSocket Events

Client:

- `envelope.submit`
- `envelope.ack`
- `ping`

Server:

- `envelope.deliver`
- `envelope.accepted`
- `pong`
- `token.expiring`
- generic `error`

Only one active WebSocket lease is allowed per account across all ECS tasks. Lease refreshes every
30 seconds and expires after 90 seconds if task or connection dies.

## Account Deletion

Deletion removes account, keys, push token, blocks, incoming and outgoing queued ciphertext.
Username remains unavailable for 30 days.

Duress secret must contain at least 128 bits of entropy. Backend stores Argon2id verifier only.
Endpoint always returns generic `202` response, including missing account, wrong secret, malformed
input, and rate-limit cases.

## Metadata Limitations

E2EE does not hide recipient routing ID, sender authentication, timing, ciphertext size, IP address,
push token, or block relationship from backend/AWS. No presence, typing, last-seen, contacts, or
analytics records exist.
