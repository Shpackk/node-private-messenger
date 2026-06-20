import { createHash, pbkdf2, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { canonicalEnvelopeBytes, type EnvelopeSubmitRequest } from "@prototype/contracts";
import type { Clock, DemoCryptoProvider, IdGenerator, PasswordHasher } from "./ports.js";
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
