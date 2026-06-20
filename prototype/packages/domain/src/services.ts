import {
	ACCESS_TOKEN_SECONDS,
	EnvelopeSubmitRequest,
	MAX_ENVELOPE_BYTES,
	REFRESH_TOKEN_SECONDS,
	decodedBase64UrlBytes,
	normalizeUsername,
	type AuthTokensResponse,
} from "@prototype/contracts";
import type { z } from "zod";
import type {
	AccountStore,
	AuthChallengeStore,
	BlockStore,
	Clock,
	DemoCryptoProvider,
	EnvelopeStore,
	IdGenerator,
	KeyStore,
	PasswordHasher,
	PushGateway,
	TokenStore,
} from "./ports.js";
import { type TokenIssuer, hashToken } from "./tokens.js";

export class DomainError extends Error {
	constructor(
		readonly code: string,
		message = code,
	) {
		super(message);
	}
}

export class MessengerService {
	constructor(
		private readonly accounts: AccountStore,
		private readonly challenges: AuthChallengeStore,
		private readonly tokens: TokenStore,
		private readonly keys: KeyStore,
		private readonly blocks: BlockStore,
		private readonly envelopes: EnvelopeStore,
		private readonly push: PushGateway,
		private readonly hasher: PasswordHasher,
		private readonly crypto: DemoCryptoProvider,
		private readonly clock: Clock,
		private readonly ids: IdGenerator,
		private readonly issuer: TokenIssuer,
	) {}

	async createAccount(input: { username: string; password: string; displayName?: string; duressPassword?: string }) {
		const username = normalizeUsername(input.username);
		if (await this.accounts.findByUsername(username)) throw new DomainError("USERNAME_TAKEN");
		return this.accounts.create({
			...input,
			username,
			passwordVerifier: await this.hasher.hash(input.password),
			duressVerifier: input.duressPassword ? await this.hasher.hash(input.duressPassword) : null,
		});
	}

	async createChallenge(usernameRaw: string) {
		const username = normalizeUsername(usernameRaw);
		const account = await this.accounts.findByUsername(username);
		if (!account || account.deletedAt) throw new DomainError("UNAUTHORIZED");
		return this.challenges.create(
			account.accountId,
			this.ids.randomToken(24),
			new Date(this.clock.now().getTime() + 120000),
		);
	}

	async verifyChallenge(input: { challengeId: string; username: string; password: string }): Promise<
		z.infer<typeof AuthTokensResponse>
	> {
		const challenge = await this.challenges.consume(input.challengeId);
		const account = await this.accounts.findByUsername(normalizeUsername(input.username));
		if (!challenge || !account || account.accountId !== challenge.accountId || account.deletedAt)
			throw new DomainError("UNAUTHORIZED");
		if (!(await this.hasher.verify(input.password, account.passwordVerifier)))
			throw new DomainError("UNAUTHORIZED");
		return this.issueTokens(account);
	}

	async refresh(refreshToken: string): Promise<z.infer<typeof AuthTokensResponse>> {
		const consumed = await this.tokens.consumeRefreshToken(hashToken(refreshToken));
		if (!consumed || consumed.expiresAt <= this.clock.now()) throw new DomainError("UNAUTHORIZED");
		const account = await this.accounts.findById(consumed.accountId);
		if (!account || account.deletedAt) throw new DomainError("UNAUTHORIZED");
		return this.issueTokens(account);
	}

	async issueTokens(account: {
		accountId: string;
		username: string;
		displayName: string | null;
		discoverable: boolean;
		tokenVersion: number;
	}) {
		const access = this.issuer.accessToken(account);
		const refreshToken = this.issuer.refreshToken();
		await this.tokens.saveRefreshToken(
			account.accountId,
			hashToken(refreshToken),
			new Date(this.clock.now().getTime() + REFRESH_TOKEN_SECONDS * 1000),
		);
		return {
			account: {
				accountId: account.accountId,
				username: account.username,
				displayName: account.displayName,
				discoverable: account.discoverable,
			},
			accessToken: access.token,
			refreshToken,
			expiresAt: access.expiresAt.toISOString(),
		};
	}

	async discover(usernameRaw: string) {
		const account = await this.accounts.findByUsername(normalizeUsername(usernameRaw));
		if (!account || account.deletedAt || !account.discoverable) throw new DomainError("NOT_FOUND");
		return { accountId: account.accountId, username: account.username, displayName: account.displayName };
	}

	async submitEnvelope(inputRaw: unknown) {
		const input = EnvelopeSubmitRequest.parse(inputRaw);
		const byteSize = decodedBase64UrlBytes(input.ciphertext);
		if (byteSize > MAX_ENVELOPE_BYTES) throw new DomainError("BAD_REQUEST", "ciphertext too large");
		if (!(await this.crypto.verifyEnvelopeSignature(input)))
			throw new DomainError("BAD_REQUEST", "invalid signature");
		const recipient = await this.accounts.findById(input.recipientAccountId);
		if (
			!recipient ||
			recipient.deletedAt ||
			(await this.blocks.hasBlockEitherWay(input.senderAccountId, input.recipientAccountId))
		) {
			throw new DomainError("RECIPIENT_UNAVAILABLE");
		}
		return this.envelopes.enqueue({
			...input,
			envelopeId: this.ids.uuid(),
			byteSize,
			expiresAt: new Date(this.clock.now().getTime() + input.ttlSeconds * 1000),
		});
	}

	leaseEnvelopes(accountId: string) {
		return this.envelopes.lease(accountId, this.ids.uuid(), new Date(this.clock.now().getTime() + 30000), 100);
	}

	async ack(accountId: string, envelopeIds: string[]) {
		return this.envelopes.ack(accountId, envelopeIds);
	}

	async deleteAccount(accountId: string) {
		const account = await this.accounts.findById(accountId);
		if (account) await this.accounts.reserveUsername(account.username);
		await this.tokens.revokeAccountTokens(accountId);
		await this.accounts.softDelete(accountId);
	}

	async duressDelete(usernameRaw: string, password: string) {
		const account = await this.accounts.findByUsername(normalizeUsername(usernameRaw));
		if (account?.duressVerifier && (await this.hasher.verify(password, account.duressVerifier))) {
			await this.deleteAccount(account.accountId);
		}
		return { ok: true };
	}

	tokenExpiresSoon(expiresAt: Date) {
		return expiresAt.getTime() - this.clock.now().getTime() < ACCESS_TOKEN_SECONDS * 500;
	}
}
