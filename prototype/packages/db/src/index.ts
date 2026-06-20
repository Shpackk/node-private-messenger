import pg from "pg";
import type Redis from "ioredis";
import { randomUUID } from "node:crypto";
import {
	type AccountCreateRequest,
	QUEUE_MAX_BYTES,
	QUEUE_MAX_ENVELOPES,
	type EnvelopeRecord,
	type EnvelopeSubmitRequest,
	type KeyBundle,
	type PushTokenRequest,
} from "@prototype/contracts";
import type { z } from "zod";
import type {
	Account,
	AccountStore,
	AuthChallengeStore,
	BlockStore,
	ConnectionRegistry,
	EnvelopeStore,
	KeyStore,
	PushGateway,
	RateLimiter,
	TokenStore,
} from "@prototype/domain";
import { DomainError } from "@prototype/domain";
import { migrations } from "./migrations.js";

export const { Pool } = pg;
export type PgPool = pg.Pool;

export async function migrate(pool: PgPool) {
	for (const sql of migrations) await pool.query(sql);
}

type AccountRow = {
	account_id: string;
	username: string;
	display_name: string | null;
	discoverable: boolean;
	password_verifier: string;
	token_version: number;
	deleted_at: Date | null;
	duress_verifier: string | null;
};

type EnvelopeRow = {
	envelope_id: string;
	recipient_account_id: string;
	sender_account_id: string;
	client_message_id: string;
	ciphertext: string;
	signature: string;
	byte_size: number;
	expires_at: Date | string;
	lease_id: string | null;
};

type CreateAccountInput = z.infer<typeof AccountCreateRequest> & {
	passwordVerifier: string;
	duressVerifier?: string | null;
};

type EnqueueEnvelopeInput = z.infer<typeof EnvelopeSubmitRequest> & {
	envelopeId: string;
	byteSize: number;
	expiresAt: Date;
};

function rowAccount(row: AccountRow): Account {
	return {
		accountId: row.account_id,
		username: row.username,
		displayName: row.display_name,
		discoverable: row.discoverable,
		passwordVerifier: row.password_verifier,
		tokenVersion: row.token_version,
		deletedAt: row.deleted_at,
		duressVerifier: row.duress_verifier,
	};
}

function rowEnvelope(row: EnvelopeRow): z.infer<typeof EnvelopeRecord> {
	return {
		envelopeId: row.envelope_id,
		recipientAccountId: row.recipient_account_id,
		senderAccountId: row.sender_account_id,
		clientMessageId: row.client_message_id,
		ciphertext: row.ciphertext,
		signature: row.signature,
		byteSize: row.byte_size,
		expiresAt: new Date(row.expires_at).toISOString(),
		leaseId: row.lease_id,
	};
}

export class PgAccountStore implements AccountStore {
	constructor(private readonly pool: PgPool) {}

	async create(input: CreateAccountInput): Promise<Account> {
		const reserved = await this.pool.query(
			"SELECT 1 FROM username_reservations WHERE username=$1 AND reserved_until > now()",
			[input.username],
		);
		if (reserved.rowCount) throw new DomainError("USERNAME_TAKEN");
		try {
			const result = await this.pool.query(
				`INSERT INTO accounts(username, display_name, password_verifier, duress_verifier)
       VALUES ($1,$2,$3,$4) RETURNING *`,
				[input.username, input.displayName ?? null, input.passwordVerifier, input.duressVerifier ?? null],
			);
			return rowAccount(result.rows[0]);
		} catch (error) {
			if (error && typeof error === "object" && "code" in error && error.code === "23505")
				throw new DomainError("USERNAME_TAKEN");
			throw error;
		}
	}

	async findByUsername(username: string) {
		const result = await this.pool.query("SELECT * FROM accounts WHERE username=$1", [username]);
		return result.rows[0] ? rowAccount(result.rows[0]) : null;
	}

	async findById(accountId: string) {
		const result = await this.pool.query("SELECT * FROM accounts WHERE account_id=$1", [accountId]);
		return result.rows[0] ? rowAccount(result.rows[0]) : null;
	}

	async findByIds(accountIds: string[]) {
		if (!accountIds.length) return [];
		const result = await this.pool.query("SELECT * FROM accounts WHERE account_id = ANY($1::uuid[])", [accountIds]);
		return result.rows.map(rowAccount);
	}

	async setDiscovery(accountId: string, discoverable: boolean) {
		await this.pool.query("UPDATE accounts SET discoverable=$2 WHERE account_id=$1", [accountId, discoverable]);
	}

	async softDelete(accountId: string) {
		await this.pool.query(
			"UPDATE accounts SET deleted_at=now(), token_version=token_version+1, discoverable=false WHERE account_id=$1",
			[accountId],
		);
	}

	async reserveUsername(username: string) {
		await this.pool.query(
			`INSERT INTO username_reservations(username, reserved_until)
       VALUES ($1, now() + interval '30 days')
       ON CONFLICT(username) DO UPDATE SET reserved_until=excluded.reserved_until`,
			[username],
		);
	}
}

export class PgTokenStore implements TokenStore {
	constructor(private readonly pool: PgPool) {}
	async saveRefreshToken(accountId: string, tokenHash: string, expiresAt: Date) {
		await this.pool.query("INSERT INTO refresh_tokens(token_hash, account_id, expires_at) VALUES($1,$2,$3)", [
			tokenHash,
			accountId,
			expiresAt,
		]);
	}
	async consumeRefreshToken(tokenHash: string) {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const result = await client.query(
				"SELECT * FROM refresh_tokens WHERE token_hash=$1 AND revoked_at IS NULL FOR UPDATE",
				[tokenHash],
			);
			if (!result.rows[0]) {
				await client.query("COMMIT");
				return null;
			}
			await client.query("UPDATE refresh_tokens SET revoked_at=now() WHERE token_hash=$1", [tokenHash]);
			await client.query("COMMIT");
			return { accountId: result.rows[0].account_id, expiresAt: result.rows[0].expires_at };
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}
	async revokeAccountTokens(accountId: string) {
		await this.pool.query("UPDATE refresh_tokens SET revoked_at=now() WHERE account_id=$1 AND revoked_at IS NULL", [
			accountId,
		]);
	}
}

export class PgKeyStore implements KeyStore {
	constructor(private readonly pool: PgPool) {}
	async put(accountId: string, bundle: z.infer<typeof KeyBundle>) {
		await this.pool.query(
			`INSERT INTO prekeys(account_id, identity_key, signed_pre_key, signed_pre_key_signature, one_time_pre_keys)
       VALUES($1,$2,$3,$4,$5)
       ON CONFLICT(account_id) DO UPDATE SET identity_key=$2, signed_pre_key=$3, signed_pre_key_signature=$4, one_time_pre_keys=$5, updated_at=now()`,
			[accountId, bundle.identityKey, bundle.signedPreKey, bundle.signedPreKeySignature, bundle.oneTimePreKeys],
		);
	}
	async get(accountId: string) {
		const result = await this.pool.query("SELECT * FROM prekeys WHERE account_id=$1", [accountId]);
		const row = result.rows[0];
		return row
			? {
					accountId,
					identityKey: row.identity_key,
					signedPreKey: row.signed_pre_key,
					signedPreKeySignature: row.signed_pre_key_signature,
					oneTimePreKeys: row.one_time_pre_keys,
				}
			: null;
	}
	async consumeOneTimePreKey(accountId: string) {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const result = await client.query("SELECT one_time_pre_keys FROM prekeys WHERE account_id=$1 FOR UPDATE", [
				accountId,
			]);
			const keys = result.rows[0]?.one_time_pre_keys ?? [];
			const key = keys.shift() ?? null;
			await client.query("UPDATE prekeys SET one_time_pre_keys=$2 WHERE account_id=$1", [accountId, keys]);
			await client.query("COMMIT");
			return key;
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}
}

export class PgBlockStore implements BlockStore {
	constructor(private readonly pool: PgPool) {}
	async block(blockerAccountId: string, blockeeAccountId: string) {
		await this.pool.query(
			"INSERT INTO blocks(blocker_account_id, blockee_account_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
			[blockerAccountId, blockeeAccountId],
		);
	}
	async unblock(blockerAccountId: string, blockeeAccountId: string) {
		await this.pool.query("DELETE FROM blocks WHERE blocker_account_id=$1 AND blockee_account_id=$2", [
			blockerAccountId,
			blockeeAccountId,
		]);
	}
	async hasBlockEitherWay(a: string, b: string) {
		const result = await this.pool.query(
			"SELECT 1 FROM blocks WHERE (blocker_account_id=$1 AND blockee_account_id=$2) OR (blocker_account_id=$2 AND blockee_account_id=$1) LIMIT 1",
			[a, b],
		);
		return Boolean(result.rowCount);
	}
}

export class PgEnvelopeStore implements EnvelopeStore {
	constructor(private readonly pool: PgPool) {}
	async enqueue(input: EnqueueEnvelopeInput) {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await client.query("INSERT INTO queue_counters(recipient_account_id) VALUES($1) ON CONFLICT DO NOTHING", [
				input.recipientAccountId,
			]);
			const counter = await client.query(
				"SELECT * FROM queue_counters WHERE recipient_account_id=$1 FOR UPDATE",
				[input.recipientAccountId],
			);
			const row = counter.rows[0];
			if (row.envelope_count + 1 > QUEUE_MAX_ENVELOPES || row.byte_count + input.byteSize > QUEUE_MAX_BYTES)
				throw new DomainError("QUEUE_FULL");
			const inserted = await client.query(
				`INSERT INTO envelopes(envelope_id, recipient_account_id, sender_account_id, client_message_id, ciphertext, signature, byte_size, expires_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
				[
					input.envelopeId,
					input.recipientAccountId,
					input.senderAccountId,
					input.clientMessageId,
					input.ciphertext,
					input.signature,
					input.byteSize,
					input.expiresAt,
				],
			);
			await client.query(
				"UPDATE queue_counters SET envelope_count=envelope_count+1, byte_count=byte_count+$2 WHERE recipient_account_id=$1",
				[input.recipientAccountId, input.byteSize],
			);
			await client.query("COMMIT");
			return rowEnvelope(inserted.rows[0]);
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}
	async lease(recipientAccountId: string, leaseId: string, leasedUntil: Date, limit: number) {
		const result = await this.pool.query(
			`UPDATE envelopes SET lease_id=$2, leased_until=$3
       WHERE envelope_id IN (
        SELECT envelope_id FROM envelopes
        WHERE recipient_account_id=$1 AND expires_at > now() AND (leased_until IS NULL OR leased_until < now())
        ORDER BY created_at ASC
        LIMIT $4 FOR UPDATE SKIP LOCKED
       ) RETURNING *`,
			[recipientAccountId, leaseId, leasedUntil, limit],
		);
		return result.rows.map(rowEnvelope);
	}
	async ack(recipientAccountId: string, envelopeIds: string[]) {
		if (!envelopeIds.length) return 0;
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const deleted = await client.query(
				"DELETE FROM envelopes WHERE recipient_account_id=$1 AND envelope_id = ANY($2::uuid[]) RETURNING byte_size",
				[recipientAccountId, envelopeIds],
			);
			const bytes = deleted.rows.reduce((sum: number, row: { byte_size: number }) => sum + row.byte_size, 0);
			await client.query(
				`INSERT INTO queue_counters(recipient_account_id, envelope_count, byte_count) VALUES($1,0,0)
         ON CONFLICT(recipient_account_id) DO UPDATE SET
         envelope_count=GREATEST(queue_counters.envelope_count-$2, 0),
         byte_count=GREATEST(queue_counters.byte_count-$3, 0)`,
				[recipientAccountId, deleted.rowCount ?? 0, bytes],
			);
			await client.query("COMMIT");
			return deleted.rowCount ?? 0;
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}
	async cleanupExpired(now: Date) {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const deleted = await client.query(
				"DELETE FROM envelopes WHERE expires_at <= $1 RETURNING recipient_account_id, byte_size",
				[now],
			);
			const byRecipient = new Map<string, { count: number; bytes: number }>();
			for (const row of deleted.rows) {
				const current = byRecipient.get(row.recipient_account_id) ?? { count: 0, bytes: 0 };
				current.count++;
				current.bytes += row.byte_size;
				byRecipient.set(row.recipient_account_id, current);
			}
			for (const [recipient, values] of byRecipient) {
				await client.query(
					"UPDATE queue_counters SET envelope_count=GREATEST(envelope_count-$2,0), byte_count=GREATEST(byte_count-$3,0) WHERE recipient_account_id=$1",
					[recipient, values.count, values.bytes],
				);
			}
			await client.query("COMMIT");
			return deleted.rowCount ?? 0;
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}
}

export class PgPushGateway implements PushGateway {
	constructor(private readonly pool: PgPool) {}
	async saveToken(accountId: string, input: z.infer<typeof PushTokenRequest>) {
		await this.pool.query(
			`INSERT INTO push_tokens(account_id, platform, token) VALUES($1,$2,$3)
       ON CONFLICT(account_id, platform, token) DO UPDATE SET updated_at=now()`,
			[accountId, input.platform, input.token],
		);
	}
	async wake(accountId: string, reason: string) {
		await this.pool.query("INSERT INTO push_wakeups(account_id, reason) VALUES($1,$2)", [accountId, reason]);
	}
}

export class RedisChallengeStore implements AuthChallengeStore {
	constructor(private readonly redis: Redis) {}
	async create(accountId: string, nonce: string, expiresAt: Date) {
		const challengeId = randomUUID();
		await this.redis.set(
			`challenge:${challengeId}`,
			JSON.stringify({ accountId, nonce, expiresAt: expiresAt.toISOString() }),
			"EX",
			120,
		);
		return { challengeId, nonce, expiresAt };
	}
	async consume(challengeId: string) {
		const key = `challenge:${challengeId}`;
		const value = (await this.redis.call("GETDEL", key)) as string | null;
		if (!value) return null;
		const parsed = JSON.parse(value);
		return { accountId: parsed.accountId, nonce: parsed.nonce, expiresAt: new Date(parsed.expiresAt) };
	}
}

export class RedisRateLimiter implements RateLimiter {
	constructor(private readonly redis: Redis) {}
	async check(scope: string, key: string, limit: number, windowSeconds: number) {
		const redisKey = `rate:${scope}:${key}`;
		const count = await this.redis.incr(redisKey);
		if (count === 1) await this.redis.expire(redisKey, windowSeconds);
		return count <= limit;
	}
}

export class RedisConnectionRegistry implements ConnectionRegistry {
	constructor(private readonly redis: Redis) {}
	async claim(accountId: string, connectionId: string, ttlSeconds: number) {
		const previous = (await this.redis.eval(
			`
local previous = redis.call("GET", KEYS[1])
redis.call("SET", KEYS[1], ARGV[1], "EX", ARGV[3])
redis.call("SET", KEYS[2], ARGV[2], "EX", ARGV[3])
return previous
`,
			2,
			`ws:owner:${accountId}`,
			`ws:conn:${connectionId}`,
			connectionId,
			accountId,
			String(ttlSeconds),
		)) as string | null;
		return previous && previous !== connectionId ? previous : null;
	}
	async refresh(accountId: string, connectionId: string, ttlSeconds: number) {
		await this.redis.set(`ws:owner:${accountId}`, connectionId, "EX", ttlSeconds);
		await this.redis.set(`ws:conn:${connectionId}`, accountId, "EX", ttlSeconds);
	}
	async release(accountId: string, connectionId: string) {
		const owner = await this.redis.get(`ws:owner:${accountId}`);
		if (owner === connectionId) await this.redis.del(`ws:owner:${accountId}`);
		await this.redis.del(`ws:conn:${connectionId}`);
	}
	async owner(accountId: string) {
		return this.redis.get(`ws:owner:${accountId}`);
	}
	async publish(accountId: string, event: unknown) {
		await this.redis.publish(`deliver:${accountId}`, JSON.stringify(event));
	}
	async subscribe(accountId: string, onEvent: (event: unknown) => void) {
		const subscriber = this.redis.duplicate();
		const channel = `deliver:${accountId}`;
		subscriber.on("message", (_channel, message) => onEvent(JSON.parse(message)));
		await subscriber.subscribe(channel);
		return async () => {
			await subscriber.unsubscribe(channel);
			subscriber.disconnect();
		};
	}
}
