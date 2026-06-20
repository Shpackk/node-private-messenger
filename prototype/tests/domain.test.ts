import { describe, expect, it } from "vitest";
import {
	DemoCrypto,
	NodeIdGenerator,
	Pbkdf2PasswordHasher,
	SystemClock,
	TokenIssuer,
} from "../packages/domain/src/index.js";
import { canonicalEnvelopeBytes } from "../packages/contracts/src/index.js";

describe("domain primitives", () => {
	it("rotates refresh token hash input by consuming store token once", async () => {
		const ids = new NodeIdGenerator();
		const clock = new SystemClock();
		const issuer = new TokenIssuer("test", clock, ids);
		const first = issuer.refreshToken();
		const second = issuer.refreshToken();
		expect(first).not.toBe(second);
	});

	it("verifies demo envelope signature over canonical bytes", async () => {
		const input = {
			recipientAccountId: "00000000-0000-4000-8000-000000000001",
			senderAccountId: "00000000-0000-4000-8000-000000000002",
			clientMessageId: "00000000-0000-4000-8000-000000000003",
			ciphertext: "YWJj",
			ttlSeconds: 60,
			signature: "",
		};
		const signature = Buffer.from(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalEnvelopeBytes(input))),
		).toString("base64url");
		await expect(new DemoCrypto().verifyEnvelopeSignature({ ...input, signature })).resolves.toBe(true);
	});

	it("hashes passwords", async () => {
		const hasher = new Pbkdf2PasswordHasher();
		const verifier = await hasher.hash("password123");
		await expect(hasher.verify("password123", verifier)).resolves.toBe(true);
		await expect(hasher.verify("bad", verifier)).resolves.toBe(false);
	});
});
