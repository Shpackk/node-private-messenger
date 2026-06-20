import { serve } from "@hono/node-server";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import Redis from "ioredis";
import { WebSocketServer, type WebSocket } from "ws";
import {
	AccountCreateRequest,
	AuthChallengeRequest,
	AuthVerifyRequest,
	BlockRequest,
	DiscoveryUpdateRequest,
	EnvelopeAckRequest,
	EnvelopeSubmitRequest,
	KeyBundle,
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
} from "@prototype/db";

const port = Number(process.env.PORT ?? 3000);
const databaseUrl = process.env.DATABASE_URL ?? "postgres://messenger:messenger@localhost:5432/messenger";
const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379";
const tokenSecret = process.env.TOKEN_SECRET ?? "local-dev-secret";

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
				: error.code === "NOT_FOUND"
					? 404
					: error.code === "USERNAME_TAKEN"
						? 409
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

const app = new Hono();
app.use("*", cors());

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

app.onError((error, c) => {
	const mapped = mapError(error);
	return c.json(mapped.body, mapped.status);
});

app.post("/v1/accounts", async (c) =>
	c.json(await service.createAccount(AccountCreateRequest.parse(await c.req.json()))),
);
app.post("/v1/auth/challenges", async (c) => {
	const body = AuthChallengeRequest.parse(await c.req.json());
	const challenge = await service.createChallenge(body.username);
	return c.json({ ...challenge, expiresAt: challenge.expiresAt.toISOString() });
});
app.post("/v1/auth/verify", async (c) =>
	c.json(await service.verifyChallenge(AuthVerifyRequest.parse(await c.req.json()))),
);
app.post("/v1/auth/refresh", async (c) =>
	c.json(await service.refresh(RefreshRequest.parse(await c.req.json()).refreshToken)),
);
app.get("/v1/usernames/:username/available", async (c) => {
	const existing = await accounts.findByUsername(c.req.param("username").trim().toLowerCase());
	return c.json({ available: !existing || Boolean(existing.deletedAt) });
});
app.put("/v1/discovery", async (c) => {
	const account = await auth(c);
	await accounts.setDiscovery(account.accountId, DiscoveryUpdateRequest.parse(await c.req.json()).discoverable);
	return c.json({ ok: true });
});
app.delete("/v1/discovery", async (c) => {
	const account = await auth(c);
	await accounts.setDiscovery(account.accountId, false);
	return c.json({ ok: true });
});
app.get("/v1/discovery/:username", async (c) => c.json(await service.discover(c.req.param("username"))));
app.post("/v1/keys", async (c) => {
	const account = await auth(c);
	await keys.put(account.accountId, KeyBundle.parse(await c.req.json()));
	return c.json({ ok: true });
});
app.get("/v1/keys/:accountId", async (c) => {
	const bundle = await keys.get(c.req.param("accountId"));
	if (!bundle) throw new DomainError("NOT_FOUND");
	const oneTimePreKey = await keys.consumeOneTimePreKey(c.req.param("accountId"));
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
	await push.saveToken(account.accountId, PushTokenRequest.parse(await c.req.json()));
	return c.json({ ok: true });
});
app.post("/v1/envelopes", async (c) => {
	const account = await auth(c);
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
	const leased = await service.leaseEnvelopes(account.accountId);
	return c.json({ leaseId: leased[0]?.leaseId ?? ids.uuid(), envelopes: await Promise.all(leased.map(withSender)) });
});
app.post("/v1/envelopes/ack", async (c) => {
	const account = await auth(c);
	const body = EnvelopeAckRequest.parse(await c.req.json());
	return c.json({ acknowledged: await service.ack(account.accountId, body.envelopeIds) });
});
app.delete("/v1/account", async (c) => {
	const account = await auth(c);
	await service.deleteAccount(account.accountId);
	return c.json({ ok: true });
});
app.post("/v1/account/duress-delete", async (c) => {
	const body = await c.req.json();
	return c.json(await service.duressDelete(String(body.username ?? ""), String(body.password ?? "")));
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
	wss.handleUpgrade(request, socket, head, (ws) => wss.emit("connection", ws, request, account.accountId, token));
});

wss.on("connection", async (ws: WebSocket, _request: unknown, accountId: string) => {
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
	const expiring = setInterval(
		() =>
			ws.readyState === ws.OPEN &&
			ws.send(JSON.stringify({ type: "token.expiring", expiresAt: new Date(Date.now() + 60000).toISOString() })),
		9 * 60000,
	);
	ws.on("message", async (raw) => {
		try {
			const event = WsClientEvent.parse(JSON.parse(raw.toString()));
			if (event.type === "ping") ws.send(JSON.stringify({ type: "pong", id: event.id }));
			if (event.type === "envelope.ack") await service.ack(accountId, event.payload.envelopeIds);
			if (event.type === "envelope.submit") {
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
		sockets.delete(connectionId);
		await unsubscribe();
		await registry.release(accountId, connectionId);
	});
});
