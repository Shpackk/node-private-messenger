import { createHmac, createHash } from "node:crypto";
import { ACCESS_TOKEN_SECONDS } from "@prototype/contracts";
import type { Clock, IdGenerator } from "./ports.js";

export type AccessClaims = {
	sub: string;
	username: string;
	tokenVersion: number;
	exp: number;
};

function b64(input: unknown): string {
	return Buffer.from(JSON.stringify(input)).toString("base64url");
}

export function hashToken(token: string): string {
	return createHash("sha256").update(token).digest("base64url");
}

export class TokenIssuer {
	constructor(
		private readonly secret: string,
		private readonly clock: Clock,
		private readonly ids: IdGenerator,
	) {}

	accessToken(account: { accountId: string; username: string; tokenVersion: number }): {
		token: string;
		expiresAt: Date;
	} {
		const expiresAt = new Date(this.clock.now().getTime() + ACCESS_TOKEN_SECONDS * 1000);
		const claims: AccessClaims = {
			sub: account.accountId,
			username: account.username,
			tokenVersion: account.tokenVersion,
			exp: Math.floor(expiresAt.getTime() / 1000),
		};
		const header = b64({ alg: "HS256", typ: "JWT" });
		const payload = b64(claims);
		const signature = createHmac("sha256", this.secret).update(`${header}.${payload}`).digest("base64url");
		return { token: `${header}.${payload}.${signature}`, expiresAt };
	}

	verifyAccessToken(token: string): AccessClaims | null {
		const [header, payload, signature] = token.split(".");
		if (!header || !payload || !signature) return null;
		const expected = createHmac("sha256", this.secret).update(`${header}.${payload}`).digest("base64url");
		if (signature !== expected) return null;
		const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as AccessClaims;
		if (claims.exp <= Math.floor(this.clock.now().getTime() / 1000)) return null;
		return claims;
	}

	refreshToken(): string {
		return this.ids.randomToken(48);
	}
}
