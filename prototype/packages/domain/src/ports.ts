import type { z } from "zod";
import type {
	AccountCreateRequest,
	AccountResponse,
	EnvelopeSubmitRequest,
	KeyBundle,
	PushTokenRequest,
} from "@prototype/contracts";

export type Account = z.infer<typeof AccountResponse> & {
	passwordVerifier: string;
	tokenVersion: number;
	deletedAt: Date | null;
	duressVerifier: string | null;
};

export interface AccountStore {
	create(
		input: z.infer<typeof AccountCreateRequest> & { passwordVerifier: string; duressVerifier?: string | null },
	): Promise<Account>;
	findByUsername(username: string): Promise<Account | null>;
	findById(accountId: string): Promise<Account | null>;
	findByIds(accountIds: string[]): Promise<Account[]>;
	setDiscovery(accountId: string, discoverable: boolean): Promise<void>;
	softDelete(accountId: string): Promise<void>;
	reserveUsername(username: string): Promise<void>;
}

export interface AuthChallengeStore {
	create(
		accountId: string,
		nonce: string,
		expiresAt: Date,
	): Promise<{ challengeId: string; nonce: string; expiresAt: Date }>;
	consume(challengeId: string): Promise<{ accountId: string; nonce: string; expiresAt: Date } | null>;
}

export interface TokenStore {
	saveRefreshToken(accountId: string, tokenHash: string, expiresAt: Date): Promise<void>;
	consumeRefreshToken(tokenHash: string): Promise<{ accountId: string; expiresAt: Date } | null>;
	revokeAccountTokens(accountId: string): Promise<void>;
}

export interface KeyStore {
	put(accountId: string, bundle: z.infer<typeof KeyBundle>): Promise<void>;
	get(accountId: string): Promise<(z.infer<typeof KeyBundle> & { accountId: string }) | null>;
	consumeOneTimePreKey(accountId: string): Promise<string | null>;
}

export interface BlockStore {
	block(blockerAccountId: string, blockeeAccountId: string): Promise<void>;
	unblock(blockerAccountId: string, blockeeAccountId: string): Promise<void>;
	hasBlockEitherWay(a: string, b: string): Promise<boolean>;
}

export interface EnvelopeStore {
	enqueue(
		input: z.infer<typeof EnvelopeSubmitRequest> & { envelopeId: string; byteSize: number; expiresAt: Date },
	): Promise<z.infer<typeof import("@prototype/contracts").EnvelopeRecord>>;
	lease(
		recipientAccountId: string,
		leaseId: string,
		leasedUntil: Date,
		limit: number,
	): Promise<z.infer<typeof import("@prototype/contracts").EnvelopeRecord>[]>;
	ack(recipientAccountId: string, envelopeIds: string[]): Promise<number>;
	cleanupExpired(now: Date): Promise<number>;
}

export interface ConnectionRegistry {
	claim(accountId: string, connectionId: string, ttlSeconds: number): Promise<string | null>;
	refresh(accountId: string, connectionId: string, ttlSeconds: number): Promise<void>;
	release(accountId: string, connectionId: string): Promise<void>;
	owner(accountId: string): Promise<string | null>;
	publish(accountId: string, event: unknown): Promise<void>;
	subscribe(accountId: string, onEvent: (event: unknown) => void): Promise<() => Promise<void>>;
}

export interface RateLimiter {
	check(scope: string, key: string, limit: number, windowSeconds: number): Promise<boolean>;
}

export interface PushGateway {
	saveToken(accountId: string, input: z.infer<typeof PushTokenRequest>): Promise<void>;
	wake(accountId: string, reason: string): Promise<void>;
}

export interface Clock {
	now(): Date;
}

export interface IdGenerator {
	uuid(): string;
	randomToken(bytes?: number): string;
}

export interface PasswordHasher {
	hash(password: string): Promise<string>;
	verify(password: string, verifier: string): Promise<boolean>;
}

export interface DemoCryptoProvider {
	verifyEnvelopeSignature(input: z.infer<typeof EnvelopeSubmitRequest>): Promise<boolean>;
}
