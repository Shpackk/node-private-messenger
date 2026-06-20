import { describe, expect, it } from "vitest";
import {
	EnvelopeSubmitRequest,
	canonicalEnvelopeBytes,
	normalizeUsername,
	decodedBase64UrlBytes,
	MAX_ENVELOPE_BYTES,
} from "../packages/contracts/src/index.js";

const envelope = {
	recipientAccountId: "00000000-0000-4000-8000-000000000001",
	senderAccountId: "00000000-0000-4000-8000-000000000002",
	clientMessageId: "00000000-0000-4000-8000-000000000003",
	ciphertext: "YWJj",
	signature: "c2ln",
	ttlSeconds: 60,
};

describe("contracts", () => {
	it("rejects unknown fields", () => {
		expect(() => EnvelopeSubmitRequest.parse({ ...envelope, extra: true })).toThrow();
	});

	it("normalizes usernames", () => {
		expect(normalizeUsername("  Alice_1 ")).toBe("alice_1");
	});

	it("keeps canonical envelope bytes stable", () => {
		expect(canonicalEnvelopeBytes(envelope)).toBe(
			'{"ciphertext":"YWJj","clientMessageId":"00000000-0000-4000-8000-000000000003","recipientAccountId":"00000000-0000-4000-8000-000000000001","senderAccountId":"00000000-0000-4000-8000-000000000002","ttlSeconds":60}',
		);
	});

	it("measures decoded ciphertext size", () => {
		expect(decodedBase64UrlBytes("YWJj")).toBe(3);
		expect(MAX_ENVELOPE_BYTES).toBe(16384);
	});
});
