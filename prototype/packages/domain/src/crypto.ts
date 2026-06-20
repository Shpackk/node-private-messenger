import {
	createCipheriv,
	createDecipheriv,
	createHash,
	pbkdf2,
	randomBytes,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import { createTOTPKeyURI, verifyTOTPWithGracePeriod } from "@oslojs/otp";
import { decodeBase32IgnorePadding, encodeBase32NoPadding } from "@oslojs/encoding";
import { canonicalEnvelopeBytes, type EnvelopeSubmitRequest } from "@prototype/contracts";
import type { Clock, DemoCryptoProvider, IdGenerator, MfaProvider, PasswordHasher } from "./ports.js";
import type { z } from "zod";

const pbkdf2Async = promisify(pbkdf2);

export class SystemClock implements Clock {
	now(): Date {
		return new Date();
	}
}

export class NodeIdGenerator implements IdGenerator {
	uuid(): string {
		return randomUUID();
	}

	randomToken(bytes = 32): string {
		return randomBytes(bytes).toString("base64url");
	}
}

export class Pbkdf2PasswordHasher implements PasswordHasher {
	async hash(password: string): Promise<string> {
		const salt = randomBytes(16).toString("base64url");
		const digest = (await pbkdf2Async(password, salt, 120000, 32, "sha256")).toString("base64url");
		return `pbkdf2$120000$${salt}$${digest}`;
	}

	async verify(password: string, verifier: string): Promise<boolean> {
		const [, rounds, salt, digest] = verifier.split("$");
		if (!rounds || !salt || !digest) return false;
		const roundCount = Number(rounds);
		if (!Number.isSafeInteger(roundCount) || roundCount <= 0) return false;
		const actual = (await pbkdf2Async(password, salt, roundCount, 32, "sha256")).toString("base64url");
		const actualBuffer = Buffer.from(actual);
		const expectedBuffer = Buffer.from(digest);
		return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer);
	}
}

export class TotpMfaProvider implements MfaProvider {
	generateSecret() {
		return encodeBase32NoPadding(randomBytes(20));
	}

	otpauthUrl(input: { issuer: string; accountName: string; secret: string }) {
		return createTOTPKeyURI(input.issuer, input.accountName, decodeBase32IgnorePadding(input.secret), 30, 6);
	}

	async encryptSecret(secret: string, password: string) {
		const salt = randomBytes(16).toString("base64url");
		const iv = randomBytes(12);
		const key = await pbkdf2Async(password, salt, 120000, 32, "sha256");
		const cipher = createCipheriv("aes-256-gcm", key, iv);
		const encrypted = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
		const tag = cipher.getAuthTag();
		return {
			ciphertext: Buffer.concat([encrypted, tag]).toString("base64url"),
			iv: iv.toString("base64url"),
			salt,
		};
	}

	async decryptSecret(input: { ciphertext: string; iv: string; salt: string }, password: string) {
		try {
			const payload = Buffer.from(input.ciphertext, "base64url");
			const encrypted = payload.subarray(0, -16);
			const tag = payload.subarray(-16);
			const key = await pbkdf2Async(password, input.salt, 120000, 32, "sha256");
			const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(input.iv, "base64url"));
			decipher.setAuthTag(tag);
			return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
		} catch {
			return null;
		}
	}

	verifyCode(secret: string, code: string) {
		if (!/^[0-9]{6}$/.test(code)) return false;
		try {
			return verifyTOTPWithGracePeriod(decodeBase32IgnorePadding(secret), 30, 6, code, 60);
		} catch {
			return false;
		}
	}
}

export class DemoCrypto implements DemoCryptoProvider {
	async verifyEnvelopeSignature(input: z.infer<typeof EnvelopeSubmitRequest>): Promise<boolean> {
		const expected = createHash("sha256").update(canonicalEnvelopeBytes(input)).digest("base64url");
		const actualBuffer = Buffer.from(input.signature);
		const expectedBuffer = Buffer.from(expected);
		return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer);
	}

	static encryptForDemo(plaintext: string): string {
		const body = JSON.stringify({
			v: 1,
			nonce: randomBytes(12).toString("base64url"),
			body: Buffer.from(plaintext).toString("base64url"),
		});
		return Buffer.from(body).toString("base64url");
	}

	static signEnvelope(input: Omit<z.infer<typeof EnvelopeSubmitRequest>, "signature">): string {
		return createHash("sha256")
			.update(canonicalEnvelopeBytes({ ...input, signature: "" }))
			.digest("base64url");
	}
}
