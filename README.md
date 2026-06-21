# Private Messenger Backend

Security-focused relay backend for a one-device, one-to-one E2EE messenger. Service never accepts
plaintext messages or client private keys. It stores opaque ciphertext only until authenticated
delivery acknowledgment or expiry.

## Stack

- Node.js `24.16.0`, TypeScript, Hono
- `pnpm 11.6.0` workspace
- DynamoDB single-table storage
- Redis connection ownership, pub/sub, and rate limits
- AWS SNS generic APNs/FCM wake-ups
- ECS Fargate behind HTTPS ALB
- AWS CDK infrastructure

## Workspace

- `apps/api`: HTTP/WebSocket service and production adapters
- `packages/contracts`: strict client/server wire schemas
- `packages/infra`: AWS CDK stack
- `docs/protocol.md`: signing rules, API behavior, and client contract
- `prototype/*`: Launchable prototype with PG and Redis + React/Vite app. Diverged from the AWS stack

## Security Boundary

Backend sees account/device public keys, routing IDs, timestamps, ciphertext sizes, IP addresses,
blocks, and push tokens. Backend must never receive plaintext, message types, private keys,
ratchet state, contact lists, or local history.

E2EE protocol implementation remains client responsibility. Backend verifies device signatures but
cannot validate encrypted content.

## Development

Requirements:

- Node.js `24.16.0`
- Corepack enabled
- Docker for image builds

```bash
corepack enable
corepack prepare pnpm@11.6.0 --activate
pnpm install --frozen-lockfile
pnpm check
```

Production service requires DynamoDB, Redis, AWS credentials, and environment values documented in
`apps/api/.env.example`. Production also requires `TLS_CERT_PEM` and `TLS_KEY_PEM`; task serves
HTTPS so ALB-to-ECS traffic remains encrypted.

## Deployment

Build CDK code, then supply existing public ACM certificate, Route 53 zone, domain, and Secrets
Manager secret containing `certificate` and `privateKey` JSON fields for internal task TLS.

```bash
pnpm build
pnpm cdk synth \
  -c certificateArn=arn:aws:acm:... \
  -c domainName=api.example.com \
  -c hostedZoneId=Z123 \
  -c hostedZoneName=example.com \
  -c internalTlsSecretArn=arn:aws:secretsmanager:...
```

Optional contexts: `apnsPlatformArn` and `fcmPlatformArn`.

CDK creates retained, deletion-protected DynamoDB/KMS resources. Review generated CloudFormation,
IAM, WAF limits, SNS platform credentials, GuardDuty account state, and estimated cost before
deployment.

## Operational Rules

- Maximum encrypted envelope: 16 KiB decoded ciphertext.
- Message TTL: 60 seconds to 3 days; default 3 days.
- Queue cap: 1,000 envelopes or 8 MiB per recipient.
- Delivery leases last 30 seconds.
- Access tokens last 10 minutes; rotating refresh tokens last 30 days.
- Username cooldown after deletion: 30 days.
- Logs contain operational event names only, never request bodies or identifiers.

## Production Gates
Aws stack in this repo != prototype, they are diverged.
Revisit AWS stack to allign it with prototype.
