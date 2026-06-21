# Local Messenger Prototype

Local-only prototype for durable store + ephemeral routing + strict contracts + opaque ciphertext.

## Idea

This prototype explores a private messenger where the backend stores as little user data as possible, treats message content as opaque ciphertext, and gives users control over identity, keys, contact state, and delivery lifetime. The reasoning is privacy first: minimize backend knowledge, reduce stored data, keep user protection central, and make server behavior easy to inspect during local development.

## Stack

- Postgres: durable accounts, keys, tokens, envelopes, counters, push audit rows.
- Redis: auth challenges, WebSocket ownership, rate limits, pub/sub delivery hints.
- API: Node + Hono + `ws`.
- Client: Vite React desktop browser UI.

## Run

Full Docker stack:

```bash
cd prototype
pnpm install
docker compose up --build
```

Open `http://localhost:5173`.

API listens on `http://localhost:3000`.

For faster local development, run only Postgres and Redis as Docker containers, then run API and client locally in watch mode:

```bash
cd prototype
pnpm install

docker run --name local-messenger-postgres \
  -e POSTGRES_USER=messenger \
  -e POSTGRES_PASSWORD=messenger \
  -e POSTGRES_DB=messenger \
  -p 5432:5432 \
  -d postgres:16-alpine

docker run --name local-messenger-redis \
  -p 6379:6379 \
  -d redis:7-alpine

pnpm migrate
pnpm dev:api
```

In another terminal:

```bash
cd prototype
pnpm dev:client
```

After first container creation, start existing containers with:

```bash
docker start local-messenger-postgres local-messenger-redis
```

Local `.env` defaults:

```env
DATABASE_URL=postgres://messenger:messenger@localhost:5432/messenger
REDIS_URL=redis://localhost:6379
VITE_API_BASE=http://localhost:3000
VITE_WS_BASE=ws://localhost:3000
```

## Test

```bash
cd prototype
pnpm test
```

## Protocol Notes

- Envelope ciphertext is opaque to API.
- Max decoded envelope ciphertext: 16 KiB.
- Envelope TTL: 60 seconds to 3 days.
- Queue cap: 1,000 envelopes or 8 MiB per recipient.
- Envelope lease: 30 seconds, up to 100 leased per request.
- Access tokens: 10 minutes.
- Refresh tokens: 30 days, rotated on refresh.
- One active WebSocket per account; new connection wins.
- Push gateway is local no-op and records wake-up attempts in Postgres.

Demo crypto is intentionally replaceable. It creates encrypted-looking payloads and signatures for local protocol coverage, not production E2EE.
