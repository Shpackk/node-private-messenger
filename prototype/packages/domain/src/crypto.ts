import { createHash, pbkdf2Sync, randomBytes, randomUUID } from "node:crypto";
import { canonicalEnvelopeBytes, type EnvelopeSubmitRequest } from "@prototype/contracts";
import type { Clock, DemoCryptoProvider, IdGenerator, PasswordHasher } from "./ports.js";
import type { z } from "zod";

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
		const digest = pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("base64url");
		return `pbkdf2$120000$${salt}$${digest}`;
	}

	async verify(password: string, verifier: string): Promise<boolean> {
		const [, rounds, salt, digest] = verifier.split("$");
		if (!rounds || !salt || !digest) return false;
		const actual = pbkdf2Sync(password, salt, Number(rounds), 32, "sha256").toString("base64url");
		return actual === digest;
	}
}

export class DemoCrypto implements DemoCryptoProvider {
	async verifyEnvelopeSignature(input: z.infer<typeof EnvelopeSubmitRequest>): Promise<boolean> {
		const expected = createHash("sha256").update(canonicalEnvelopeBytes(input)).digest("base64url");
		return input.signature === expected;
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
