import { describe, expect, it } from "vitest";
import {
	MAX_MESSAGE_TTL_SECONDS,
	accountCreateSchema,
	decodedBase64UrlBytes,
	envelopeSchema,
} from "./index.js";

describe("wire contracts", () => {
	it("rejects plaintext-shaped account fields", () => {
		const result = accountCreateSchema.safeParse({
			username: "alice",
			devicePublicKey: "YWJj",
			identityPublicKey: "YWJj",
			signedPreKey: "YWJj",
			signedPreKeySignature: "YWJj",
			oneTimePreKeys: [],
			password: "must-never-enter-this-schema",
		});
		expect(result.success).toBe(false);
	});

	it("enforces envelope TTL", () => {
		const result = envelopeSchema.safeParse({
			version: 1,
			envelopeId: "f26a90fa-17a3-4307-91f5-665588f44d84",
			recipientAccountId: "ea02bc11-ae5c-42d6-9ba7-665ae75277fa",
			createdAt: new Date().toISOString(),
			ttlSeconds: MAX_MESSAGE_TTL_SECONDS + 1,
			ciphertext: "YWJj",
			signature: "YWJj",
		});
		expect(result.success).toBe(false);
	});

	it("counts decoded ciphertext bytes", () => {
		expect(decodedBase64UrlBytes("aGVsbG8")).toBe(5);
	});
});
