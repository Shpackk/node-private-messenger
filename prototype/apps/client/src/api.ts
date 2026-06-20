import type { Session } from "./types";

const API = import.meta.env.VITE_API_BASE ?? "http://localhost:3000";

export class ApiError extends Error {
	constructor(
		message: string,
		readonly code?: string,
	) {
		super(message);
	}
}

export async function api<T>(path: string, options: RequestInit = {}, session?: Session): Promise<T> {
	const response = await fetch(`${API}${path}`, {
		...options,
		headers: {
			"content-type": "application/json",
			...(session ? { authorization: `Bearer ${session.accessToken}` } : {}),
			...(options.headers ?? {}),
		},
	});
	if (!response.ok) {
		const body = await response.json().catch(() => null);
		throw new ApiError(body?.error?.message ?? response.statusText, body?.error?.code);
	}
	return response.json();
}
