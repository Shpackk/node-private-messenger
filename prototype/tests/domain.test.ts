import { describe, expect, it } from "vitest";
import {
	DemoCrypto,
	NodeIdGenerator,
	Pbkdf2PasswordHasher,
	SystemClock,
	TokenIssuer,
	TotpMfaProvider,
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
		await expect(hasher.verify("password123", "pbkdf2$nan$salt$digest")).resolves.toBe(false);
	});

	it("wraps MFA secrets with the account password", async () => {
		const mfa = new TotpMfaProvider();
		const secret = mfa.generateSecret();
		const encrypted = await mfa.encryptSecret(secret, "password123");
		await expect(mfa.decryptSecret(encrypted, "password123")).resolves.toBe(secret);
		await expect(mfa.decryptSecret(encrypted, "bad")).resolves.toBeNull();
	});

	it("verifies TOTP codes with Oslo", () => {
		const mfa = new TotpMfaProvider();
		const realNow = Date.now;
		Date.now = () => 90_000;
		try {
			const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
			expect(mfa.verifyCode(secret, "287082")).toBe(true);
			expect(mfa.verifyCode(secret, "000000")).toBe(false);
		} finally {
			Date.now = realNow;
		}
	});

	it("rejects malformed access tokens without throwing", () => {
		const ids = new NodeIdGenerator();
		const clock = new SystemClock();
		const issuer = new TokenIssuer("test", clock, ids);
		expect(issuer.verifyAccessToken("not.jwt")).toBeNull();
		expect(issuer.verifyAccessToken("eyJhbGciOiJub25lIn0.e30.sig")).toBeNull();
	});
});
