import { serve } from "@hono/node-server";
import { createHash } from "node:crypto";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import Redis from "ioredis";
import { WebSocketServer, type WebSocket } from "ws";
import {
	ACCESS_TOKEN_SECONDS,
	AccountCreateRequest,
	AuthChallengeRequest,
	AuthVerifyRequest,
	BlockRequest,
	DiscoveryUpdateRequest,
	EnvelopeAckRequest,
	EnvelopeSubmitRequest,
	KeyBundle,
	MfaRegistrationSetupRequest,
	MfaSetupConfirmRequest,
	MfaSetupStartRequest,
	PushTokenRequest,
	RefreshRequest,
	WsClientEvent,
	type ErrorResponse,
} from "@prototype/contracts";
import {
	DemoCrypto,
	DomainError,
	MessengerService,
	NodeIdGenerator,
	Pbkdf2PasswordHasher,
	SystemClock,
	TokenIssuer,
	TotpMfaProvider,
} from "@prototype/domain";
import {
	migrate,
	PgAccountStore,
	PgBlockStore,
	PgEnvelopeStore,
	PgKeyStore,
	PgPushGateway,
	PgTokenStore,
	Pool,
	RedisChallengeStore,
	RedisConnectionRegistry,
	RedisRateLimiter,
} from "@prototype/db";

const port = Number(process.env.PORT ?? 3000);
const databaseUrl = process.env.DATABASE_URL ?? "postgres://messenger:messenger@localhost:5432/messenger";
const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379";
const tokenSecret = process.env.TOKEN_SECRET ?? "local-dev-secret";
const allowedOrigins = (
	process.env.CORS_ALLOWED_ORIGINS ??
	process.env.ALLOWED_ORIGINS ??
	(process.env.NODE_ENV === "production" ? "" : "http://localhost:5173,http://127.0.0.1:5173")
)
	.split(",")
	.map((origin) => origin.trim())
	.filter(Boolean);

const pool = new Pool({ connectionString: databaseUrl });
await migrate(pool);
const redis = new Redis(redisUrl);
const clock = new SystemClock();
const ids = new NodeIdGenerator();
const accounts = new PgAccountStore(pool);
const tokens = new PgTokenStore(pool);
const keys = new PgKeyStore(pool);
const blocks = new PgBlockStore(pool);
const envelopes = new PgEnvelopeStore(pool);
const push = new PgPushGateway(pool);
const registry = new RedisConnectionRegistry(redis);
const rateLimiter = new RedisRateLimiter(redis);
const issuer = new TokenIssuer(tokenSecret, clock, ids);
const service = new MessengerService(
	accounts,
	new RedisChallengeStore(redis),
	tokens,
	keys,
	blocks,
	envelopes,
	push,
	new Pbkdf2PasswordHasher(),
	new TotpMfaProvider(),
	new DemoCrypto(),
	clock,
	ids,
	issuer,
);

const sockets = new Map<string, WebSocket>();

function problem(code: string, message = code): ErrorResponse {
	return { error: { code: code as ErrorResponse["error"]["code"], message } };
}

function mapError(error: unknown): { status: ContentfulStatusCode; body: ErrorResponse } {
	if (error instanceof DomainError) {
		const status =
			error.code === "UNAUTHORIZED"
				? 401
				: error.code === "FORBIDDEN"
					? 403
					: error.code === "NOT_FOUND"
						? 404
						: error.code === "USERNAME_TAKEN" || error.code === "QUEUE_FULL"
							? 409
							: error.code === "RECIPIENT_UNAVAILABLE"
								? 503
								: error.code === "RATE_LIMITED"
									? 429
									: 400;
		return { status, body: problem(error.code, error.message) };
	}
	if (error && typeof error === "object" && "issues" in error)
		return { status: 400, body: problem("BAD_REQUEST", "schema validation failed") };
	console.error("api.error", error);
	return { status: 500, body: problem("INTERNAL") };
}

async function auth(c: Context) {
	const header = c.req.header("authorization") ?? "";
	const token = header.startsWith("Bearer ") ? header.slice(7) : "";
	const claims = issuer.verifyAccessToken(token);
	if (!claims) throw new DomainError("UNAUTHORIZED");
	const account = await accounts.findById(claims.sub);
	if (!account || account.deletedAt || account.tokenVersion !== claims.tokenVersion)
		throw new DomainError("UNAUTHORIZED");
	return account;
}

async function requireRateLimit(scope: string, key: string, limit: number, windowSeconds: number) {
	if (!(await rateLimiter.check(scope, key, limit, windowSeconds))) throw new DomainError("RATE_LIMITED");
}

function clientKey(c: Context) {
	return (
		c.req
			.header("x-forwarded-for")
			?.split(",")[0]
			?.trim() ||
		c.req.header("x-real-ip") ||
		"unknown"
	);
}

async function requireAccountRateLimit(accountId: string, action: string, limit: number, windowSeconds: number) {
	await requireRateLimit(`account.${action}`, accountId, limit, windowSeconds);
}

function rateLimitTokenKey(token: string) {
	return createHash("sha256").update(token).digest("hex");
}

const app = new Hono();
app.use("*", async (c, next) => {
	const origin = c.req.header("origin");
	if (origin && !allowedOrigins.includes(origin)) return c.json(problem("FORBIDDEN", "origin not allowed"), 403);
	await next();
});
app.use(
	"*",
	cors({
		origin: (origin) => (allowedOrigins.includes(origin) ? origin : null),
	}),
);

async function withSender(record: Awaited<ReturnType<typeof service.submitEnvelope>>) {
	const sender = await accounts.findById(record.senderAccountId);
	if (!sender || sender.deletedAt) throw new DomainError("NOT_FOUND");
	return {
		...record,
		sender: {
			accountId: sender.accountId,
			username: sender.username,
			displayName: sender.displayName,
		},
	};
}

async function withSenders(records: Awaited<ReturnType<typeof service.leaseEnvelopes>>) {
	const senderIds = [...new Set(records.map((record) => record.senderAccountId))];
	const senders = new Map((await accounts.findByIds(senderIds)).map((sender) => [sender.accountId, sender]));
	return records.map((record) => {
		const sender = senders.get(record.senderAccountId);
		if (!sender || sender.deletedAt) throw new DomainError("NOT_FOUND");
		return {
			...record,
			sender: {
				accountId: sender.accountId,
				username: sender.username,
				displayName: sender.displayName,
			},
		};
	});
}

app.onError((error, c) => {
	const mapped = mapError(error);
	return c.json(mapped.body, mapped.status);
});

app.post("/v1/accounts", async (c) => {
	const body = AccountCreateRequest.parse(await c.req.json());
	await requireRateLimit("account.create.ip", clientKey(c), 5, 3600);
	await requireRateLimit("account.create.username", body.username, 3, 3600);
	return c.json(await service.createAccount(body));
});
app.post("/v1/auth/challenges", async (c) => {
	const body = AuthChallengeRequest.parse(await c.req.json());
	await requireRateLimit("auth.challenge", body.username, 10, 60);
	const challenge = await service.createChallenge(body.username);
	return c.json({ ...challenge, expiresAt: challenge.expiresAt.toISOString() });
});
app.post("/v1/auth/verify", async (c) => {
	const body = AuthVerifyRequest.parse(await c.req.json());
	await requireRateLimit("auth.verify", body.username, 10, 60);
	return c.json(await service.verifyChallenge(body));
});
app.post("/v1/auth/refresh", async (c) => {
	const body = RefreshRequest.parse(await c.req.json());
	await requireRateLimit("auth.refresh.ip", clientKey(c), 30, 60);
	await requireRateLimit("auth.refresh.token", rateLimitTokenKey(body.refreshToken), 10, 60);
	return c.json(await service.refresh(body.refreshToken));
});
app.post("/v1/mfa/registration/setup", async (c) => {
	const body = MfaRegistrationSetupRequest.parse(await c.req.json());
	await requireRateLimit("mfa.registration", body.username, 5, 60);
	return c.json(service.createMfaRegistrationSetup(body.username));
});
app.get("/v1/usernames/:username/available", async (c) => {
	await requireRateLimit("username.available.ip", clientKey(c), 60, 60);
	const existing = await accounts.findByUsername(c.req.param("username").trim().toLowerCase());
	return c.json({ available: !existing || Boolean(existing.deletedAt) });
});
app.put("/v1/discovery", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "discovery.update", 20, 60);
	await accounts.setDiscovery(account.accountId, DiscoveryUpdateRequest.parse(await c.req.json()).discoverable);
	return c.json({ ok: true });
});
app.delete("/v1/discovery", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "discovery.delete", 20, 60);
	await accounts.setDiscovery(account.accountId, false);
	return c.json({ ok: true });
});
app.post("/v1/mfa/setup/start", async (c) => {
	const account = await auth(c);
	await requireRateLimit("mfa.setup", account.accountId, 5, 60);
	const body = MfaSetupStartRequest.parse(await c.req.json());
	return c.json(await service.startMfaSetup(account.accountId, body.password));
});
app.post("/v1/mfa/setup/confirm", async (c) => {
	const account = await auth(c);
	await requireRateLimit("mfa.confirm", account.accountId, 10, 60);
	const body = MfaSetupConfirmRequest.parse(await c.req.json());
	return c.json(await service.confirmMfaSetup(account.accountId, body));
});
app.get("/v1/discovery/:username", async (c) => {
	await requireRateLimit("discovery.lookup.ip", clientKey(c), 60, 60);
	return c.json(await service.discover(c.req.param("username")));
});
app.post("/v1/keys", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "keys.upload", 10, 60);
	await keys.put(account.accountId, KeyBundle.parse(await c.req.json()));
	return c.json({ ok: true });
});
app.get("/v1/keys/:accountId", async (c) => {
	const account = await auth(c);
	const targetAccountId = c.req.param("accountId");
	await requireRateLimit("keys.consume", `${account.accountId}:${targetAccountId}`, 30, 60);
	const bundle = await keys.get(targetAccountId);
	if (!bundle) throw new DomainError("NOT_FOUND");
	const oneTimePreKey = await keys.consumeOneTimePreKey(targetAccountId);
	return c.json({ ...bundle, oneTimePreKey });
});
app.put("/v1/blocks", async (c) => {
	const account = await auth(c);
	await blocks.block(account.accountId, BlockRequest.parse(await c.req.json()).accountId);
	return c.json({ ok: true });
});
app.delete("/v1/blocks/:accountId", async (c) => {
	const account = await auth(c);
	await blocks.unblock(account.accountId, c.req.param("accountId"));
	return c.json({ ok: true });
});
app.put("/v1/push-token", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "push-token", 10, 60);
	await push.saveToken(account.accountId, PushTokenRequest.parse(await c.req.json()));
	return c.json({ ok: true });
});
app.post("/v1/envelopes", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "envelopes.submit", 120, 60);
	const body = EnvelopeSubmitRequest.parse(await c.req.json());
	if (body.senderAccountId !== account.accountId) throw new DomainError("FORBIDDEN");
	const record = await service.submitEnvelope(body);
	const liveOwner = await registry.owner(record.recipientAccountId);
	if (liveOwner)
		await registry.publish(record.recipientAccountId, {
			type: "envelope.deliver",
			payload: await withSender(record),
		});
	else await push.wake(record.recipientAccountId, "envelope.pending");
	return c.json({ envelopeId: record.envelopeId, clientMessageId: record.clientMessageId });
});
app.get("/v1/envelopes", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "envelopes.lease", 120, 60);
	const leased = await service.leaseEnvelopes(account.accountId);
	return c.json({ leaseId: leased[0]?.leaseId ?? ids.uuid(), envelopes: await withSenders(leased) });
});
app.post("/v1/envelopes/ack", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "envelopes.ack", 120, 60);
	const body = EnvelopeAckRequest.parse(await c.req.json());
	return c.json({ acknowledged: await service.ack(account.accountId, body.envelopeIds) });
});
app.delete("/v1/account", async (c) => {
	const account = await auth(c);
	await requireAccountRateLimit(account.accountId, "delete", 3, 3600);
	await service.deleteAccount(account.accountId);
	return c.json({ ok: true });
});
app.post("/v1/account/duress-delete", async (c) => {
	const body = await c.req.json();
	const username = String(body.username ?? "");
	await requireRateLimit("account.duress-delete.ip", clientKey(c), 5, 3600);
	await requireRateLimit("account.duress-delete.username", username, 3, 3600);
	return c.json(await service.duressDelete(username, String(body.password ?? "")));
});

setInterval(() => {
	envelopes.cleanupExpired(clock.now()).catch((error) => console.error("cleanup.error", error));
}, 60000).unref();

const server = serve({ fetch: app.fetch, port }, () => console.log(`api.listen ${port}`));

const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", async (request, socket, head) => {
	if (!request.url?.startsWith("/v1/ws")) return socket.destroy();
	const protocol = request.headers["sec-websocket-protocol"];
	const raw = Array.isArray(protocol) ? protocol[0] : protocol;
	const token = raw?.startsWith("bearer.") ? raw.slice("bearer.".length) : "";
	const claims = token ? issuer.verifyAccessToken(token) : null;
	if (!claims) return socket.destroy();
	const account = await accounts.findById(claims.sub);
	if (!account || account.deletedAt || account.tokenVersion !== claims.tokenVersion) return socket.destroy();
	wss.handleUpgrade(request, socket, head, (ws) =>
		wss.emit("connection", ws, request, account.accountId, claims.exp),
	);
});

wss.on("connection", async (ws: WebSocket, _request: unknown, accountId: string, tokenExpiresAtSeconds: number) => {
	const connectionId = ids.uuid();
	const old = await registry.claim(accountId, connectionId, 90);
	if (old) {
		const oldSocket = sockets.get(old);
		oldSocket?.send(JSON.stringify(problem("FORBIDDEN", "connection replaced")));
		oldSocket?.close();
	}
	sockets.set(connectionId, ws);
	const unsubscribe = await registry.subscribe(
		accountId,
		(event) => ws.readyState === ws.OPEN && ws.send(JSON.stringify(event)),
	);
	const refresh = setInterval(() => registry.refresh(accountId, connectionId, 90).catch(() => undefined), 30000);
	const tokenExpiresAtMs = tokenExpiresAtSeconds * 1000;
	const expiring = setInterval(
		() =>
			ws.readyState === ws.OPEN && Date.now() >= tokenExpiresAtMs - ACCESS_TOKEN_SECONDS * 500
				? ws.send(
						JSON.stringify({ type: "token.expiring", expiresAt: new Date(tokenExpiresAtMs).toISOString() }),
					)
				: undefined,
		30000,
	);
	const closeOnExpiry = setTimeout(
		() => {
			if (ws.readyState === ws.OPEN) ws.close(4001, "access token expired");
		},
		Math.max(tokenExpiresAtMs - Date.now(), 0),
	);
	ws.on("message", async (raw) => {
		try {
			const event = WsClientEvent.parse(JSON.parse(raw.toString()));
			if (event.type === "ping") ws.send(JSON.stringify({ type: "pong", id: event.id }));
			if (event.type === "envelope.ack") {
				await requireRateLimit("ws.envelopes.ack", accountId, 120, 60);
				await service.ack(accountId, event.payload.envelopeIds);
			}
			if (event.type === "envelope.submit") {
				await requireRateLimit("ws.envelopes.submit", accountId, 120, 60);
				if (event.payload.senderAccountId !== accountId) throw new DomainError("FORBIDDEN");
				const record = await service.submitEnvelope(event.payload);
				ws.send(
					JSON.stringify({
						type: "envelope.accepted",
						payload: { envelopeId: record.envelopeId, clientMessageId: record.clientMessageId },
					}),
				);
				const liveOwner = await registry.owner(record.recipientAccountId);
				if (liveOwner)
					await registry.publish(record.recipientAccountId, {
						type: "envelope.deliver",
						payload: await withSender(record),
					});
				else await push.wake(record.recipientAccountId, "envelope.pending");
			}
		} catch (error) {
			ws.send(JSON.stringify({ type: "error", error: mapError(error).body.error }));
		}
	});
	ws.on("close", async () => {
		clearInterval(refresh);
		clearInterval(expiring);
		clearTimeout(closeOnExpiry);
		sockets.delete(connectionId);
		await unsubscribe();
		await registry.release(accountId, connectionId);
	});
});
