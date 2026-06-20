export async function digest(text: string) {
	const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return btoa(String.fromCharCode(...new Uint8Array(bytes)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

export function uuid() {
	return crypto.randomUUID();
}

export function demoCiphertext(text: string) {
	const body = JSON.stringify({ v: 1, nonce: uuid(), body: btoa(text) });
	return btoa(body).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string) {
	const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
	const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
	return atob(padded);
}

export function demoPlaintext(ciphertext: string) {
	try {
		const decoded = JSON.parse(fromBase64Url(ciphertext)) as { body?: string };
		return decoded.body ? atob(decoded.body) : "[could not decrypt demo ciphertext]";
	} catch {
		return "[could not decrypt demo ciphertext]";
	}
}
