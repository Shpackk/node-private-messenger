export const CONTACTS_STORAGE_PREFIX = "contacts:";
export const MESSAGES_STORAGE_PREFIX = "messages:";
export const ACTIVE_PEER_STORAGE_PREFIX = "active-peer:";

export function readStored<T>(key: string, fallback: T): T {
	try {
		return JSON.parse(localStorage.getItem(key) ?? "null") ?? fallback;
	} catch {
		return fallback;
	}
}
