import { z } from "zod";

export const PROTOCOL_VERSION = 1;
export const MIN_MESSAGE_TTL_SECONDS = 60;
export const MAX_MESSAGE_TTL_SECONDS = 3 * 24 * 60 * 60;
export const DEFAULT_MESSAGE_TTL_SECONDS = MAX_MESSAGE_TTL_SECONDS;
export const MAX_ENVELOPE_BYTES = 16 * 1024;
export const MAX_PENDING_ENVELOPES = 1_000;
export const MAX_PENDING_BYTES = 8 * 1024 * 1024;

const base64Url = z
	.string()
	.regex(/^[A-Za-z0-9_-]+$/)
	.max(32_768);
const id = z.uuid();
const username = z
	.string()
	.min(3)
	.max(32)
	.regex(/^[a-z0-9_]+$/)
	.transform((value) => value.toLowerCase());

export const accountCreateSchema = z.strictObject({
	username,
	devicePublicKey: base64Url.max(256),
	identityPublicKey: base64Url.max(256),
	signedPreKey: base64Url.max(512),
	signedPreKeySignature: base64Url.max(256),
	oneTimePreKeys: z.array(base64Url.max(256)).max(100),
	duressSecret: base64Url.min(22).max(256).optional(),
});

export const challengeRequestSchema = z.strictObject({
	username,
});

export const challengeVerifySchema = z.strictObject({
	challengeId: id,
	signature: base64Url.max(256),
});

export const refreshSchema = z.strictObject({
	refreshToken: z.string().min(32).max(2048),
	signature: base64Url.max(256),
});

export const discoverabilitySchema = z.strictObject({
	ttlSeconds: z
		.number()
		.int()
		.min(60)
		.max(24 * 60 * 60),
});

export const usernameParamSchema = z.strictObject({ username });

export const preKeyUploadSchema = z.strictObject({
	signedPreKey: base64Url.max(512).optional(),
	signedPreKeySignature: base64Url.max(256).optional(),
	oneTimePreKeys: z.array(base64Url.max(256)).min(1).max(100),
});

export const blockSchema = z.strictObject({
	accountId: id,
});

export const pushTokenSchema = z.strictObject({
	platform: z.enum(["apns", "fcm"]),
	token: z.string().min(16).max(4096),
});

export const duressDeleteSchema = z.strictObject({
	username,
	secret: base64Url.min(22).max(256),
});

export const envelopeSchema = z.strictObject({
	version: z.literal(PROTOCOL_VERSION),
	envelopeId: id,
	recipientAccountId: id,
	createdAt: z.iso.datetime({ offset: true }),
	ttlSeconds: z
		.number()
		.int()
		.min(MIN_MESSAGE_TTL_SECONDS)
		.max(MAX_MESSAGE_TTL_SECONDS)
		.default(DEFAULT_MESSAGE_TTL_SECONDS),
	ciphertext: base64Url,
	signature: base64Url.max(256),
});

export const acknowledgmentSchema = z.strictObject({
	envelopeIds: z.array(id).min(1).max(100),
});

export const websocketClientEventSchema = z.discriminatedUnion("type", [
	z.strictObject({ type: z.literal("envelope.submit"), payload: envelopeSchema }),
	z.strictObject({ type: z.literal("envelope.ack"), payload: acknowledgmentSchema }),
	z.strictObject({ type: z.literal("ping"), requestId: z.string().max(64) }),
]);

export const websocketServerEventSchema = z.discriminatedUnion("type", [
	z.strictObject({ type: z.literal("envelope.deliver"), payload: envelopeSchema }),
	z.strictObject({
		type: z.literal("envelope.accepted"),
		envelopeId: id,
		queued: z.boolean(),
	}),
	z.strictObject({
		type: z.literal("error"),
		code: z.enum([
			"INVALID_EVENT",
			"UNAUTHORIZED",
			"RECIPIENT_UNAVAILABLE",
			"RATE_LIMITED",
			"INTERNAL_ERROR",
		]),
	}),
	z.strictObject({ type: z.literal("pong"), requestId: z.string().max(64) }),
	z.strictObject({ type: z.literal("token.expiring"), expiresAt: z.number().int() }),
]);

export type AccountCreateInput = z.infer<typeof accountCreateSchema>;
export type EnvelopeInput = z.infer<typeof envelopeSchema>;
export type WebSocketClientEvent = z.infer<typeof websocketClientEventSchema>;
export type WebSocketServerEvent = z.infer<typeof websocketServerEventSchema>;

export function decodedBase64UrlBytes(value: string): number {
	return Buffer.from(value, "base64url").byteLength;
}

export function canonicalEnvelopeBytes(envelope: EnvelopeInput): Uint8Array {
	const value = [
		envelope.version,
		envelope.envelopeId,
		envelope.recipientAccountId,
		envelope.createdAt,
		envelope.ttlSeconds,
		envelope.ciphertext,
	].join("\n");
	return new TextEncoder().encode(value);
}

export function canonicalSignedPreKeyBytes(signedPreKey: string): Uint8Array {
	return new TextEncoder().encode(`messenger-signed-prekey-v1\n${signedPreKey}`);
}

export function canonicalRefreshBytes(refreshToken: string): Uint8Array {
	return new TextEncoder().encode(`messenger-refresh-v1\n${refreshToken}`);
}
