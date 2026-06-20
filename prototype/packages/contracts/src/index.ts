import { z } from "zod";

export const MAX_ENVELOPE_BYTES = 16 * 1024;
export const MIN_ENVELOPE_TTL_SECONDS = 60;
export const MAX_ENVELOPE_TTL_SECONDS = 3 * 24 * 60 * 60;
export const QUEUE_MAX_ENVELOPES = 1000;
export const QUEUE_MAX_BYTES = 8 * 1024 * 1024;
export const ENVELOPE_LEASE_SECONDS = 30;
export const ACCESS_TOKEN_SECONDS = 10 * 60;
export const REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60;

export const errorCodes = [
	"BAD_REQUEST",
	"UNAUTHORIZED",
	"MFA_REQUIRED",
	"FORBIDDEN",
	"NOT_FOUND",
	"USERNAME_TAKEN",
	"RECIPIENT_UNAVAILABLE",
	"QUEUE_FULL",
	"RATE_LIMITED",
	"INTERNAL",
] as const;

export const ErrorResponse = z
	.object({
		error: z
			.object({
				code: z.enum(errorCodes),
				message: z.string(),
			})
			.strict(),
	})
	.strict();

export type ErrorResponse = z.infer<typeof ErrorResponse>;

const b64url = z.string().regex(/^[A-Za-z0-9_-]+$/);
const username = z
	.string()
	.min(3)
	.max(32)
	.regex(/^[a-z0-9_]+$/);
const accountId = z.string().uuid();

export const AccountCreateRequest = z
	.object({
		username,
		password: z.string().min(8).max(256),
		displayName: z.string().max(80).optional(),
		duressPassword: z.string().min(8).max(256).optional(),
		mfaSecret: z.string().min(16),
		mfaCode: z.string().regex(/^[0-9]{6}$/),
	})
	.strict();

export const AccountResponse = z
	.object({
		accountId,
		username,
		displayName: z.string().nullable(),
		discoverable: z.boolean(),
		mfaEnabled: z.boolean(),
	})
	.strict();

export const AuthChallengeRequest = z
	.object({
		username,
	})
	.strict();

export const AuthChallengeResponse = z
	.object({
		challengeId: z.string().uuid(),
		nonce: b64url,
		expiresAt: z.string().datetime(),
	})
	.strict();

export const AuthVerifyRequest = z
	.object({
		challengeId: z.string().uuid(),
		username,
		password: z.string().min(1).max(256),
		mfaCode: z
			.string()
			.regex(/^[0-9]{6}$/)
			.optional(),
	})
	.strict();

export const AuthTokensResponse = z
	.object({
		account: AccountResponse,
		accessToken: z.string(),
		refreshToken: z.string(),
		expiresAt: z.string().datetime(),
	})
	.strict();

export const AuthMfaRequiredResponse = z
	.object({
		mfaRequired: z.literal(true),
		challengeId: z.string().uuid(),
	})
	.strict();

export const AuthVerifyResponse = z.union([AuthTokensResponse, AuthMfaRequiredResponse]);

export const MfaSetupStartRequest = z
	.object({
		password: z.string().min(1).max(256),
	})
	.strict();

export const MfaRegistrationSetupRequest = z
	.object({
		username,
	})
	.strict();

export const MfaSetupStartResponse = z
	.object({
		secret: z.string().min(16),
		otpauthUrl: z.string().min(1),
	})
	.strict();

export const MfaSetupConfirmRequest = z
	.object({
		password: z.string().min(1).max(256),
		secret: z.string().min(16),
		code: z.string().regex(/^[0-9]{6}$/),
	})
	.strict();

export const RefreshRequest = z
	.object({
		refreshToken: z.string().min(20),
	})
	.strict();

export const DiscoveryUpdateRequest = z
	.object({
		discoverable: z.boolean(),
	})
	.strict();

export const DiscoveryResponse = z
	.object({
		accountId,
		username,
		displayName: z.string().nullable(),
	})
	.strict();

export const KeyBundle = z
	.object({
		identityKey: b64url,
		signedPreKey: b64url,
		signedPreKeySignature: b64url,
		oneTimePreKeys: z.array(b64url).max(100),
	})
	.strict();

export const KeyBundleResponse = KeyBundle.extend({
	accountId,
}).strict();

export const BlockRequest = z
	.object({
		accountId,
	})
	.strict();

export const PushTokenRequest = z
	.object({
		platform: z.enum(["ios", "android", "web", "debug"]),
		token: z.string().min(1).max(512),
	})
	.strict();

export const EnvelopeSubmitRequest = z
	.object({
		recipientAccountId: accountId,
		senderAccountId: accountId,
		clientMessageId: z.string().uuid(),
		ciphertext: b64url,
		signature: b64url,
		ttlSeconds: z.number().int().min(MIN_ENVELOPE_TTL_SECONDS).max(MAX_ENVELOPE_TTL_SECONDS),
	})
	.strict();

export const EnvelopeRecord = z
	.object({
		envelopeId: z.string().uuid(),
		recipientAccountId: accountId,
		senderAccountId: accountId,
		clientMessageId: z.string().uuid(),
		ciphertext: b64url,
		signature: b64url,
		byteSize: z.number().int().nonnegative(),
		expiresAt: z.string().datetime(),
		leaseId: z.string().uuid().nullable(),
	})
	.strict();

export const EnvelopeDeliveryRecord = EnvelopeRecord.extend({
	sender: DiscoveryResponse,
}).strict();

export const EnvelopeAcceptedResponse = z
	.object({
		envelopeId: z.string().uuid(),
		clientMessageId: z.string().uuid(),
	})
	.strict();

export const EnvelopeListResponse = z
	.object({
		leaseId: z.string().uuid(),
		envelopes: z.array(EnvelopeDeliveryRecord).max(100),
	})
	.strict();

export const EnvelopeAckRequest = z
	.object({
		envelopeIds: z.array(z.string().uuid()).max(100),
	})
	.strict();

export const EnvelopeAckResponse = z
	.object({
		acknowledged: z.number().int().nonnegative(),
	})
	.strict();

export const WsClientEvent = z.discriminatedUnion("type", [
	z.object({ type: z.literal("envelope.submit"), payload: EnvelopeSubmitRequest }).strict(),
	z.object({ type: z.literal("envelope.ack"), payload: EnvelopeAckRequest }).strict(),
	z.object({ type: z.literal("ping"), id: z.string().optional() }).strict(),
]);

export const WsServerEvent = z.discriminatedUnion("type", [
	z.object({ type: z.literal("envelope.deliver"), payload: EnvelopeDeliveryRecord }).strict(),
	z.object({ type: z.literal("envelope.accepted"), payload: EnvelopeAcceptedResponse }).strict(),
	z.object({ type: z.literal("pong"), id: z.string().optional() }).strict(),
	z.object({ type: z.literal("token.expiring"), expiresAt: z.string().datetime() }).strict(),
	z.object({ type: z.literal("error"), error: ErrorResponse.shape.error }).strict(),
]);

export function normalizeUsername(value: string): string {
	return value.trim().toLowerCase();
}

export function decodedBase64UrlBytes(value: string): number {
	const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
	const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
	return Buffer.from(padded, "base64").byteLength;
}

export function canonicalEnvelopeBytes(input: z.infer<typeof EnvelopeSubmitRequest>): string {
	return JSON.stringify({
		ciphertext: input.ciphertext,
		clientMessageId: input.clientMessageId,
		recipientAccountId: input.recipientAccountId,
		senderAccountId: input.senderAccountId,
		ttlSeconds: input.ttlSeconds,
	});
}
