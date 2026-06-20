import { useEffect, useRef, type MutableRefObject } from "react";
import { WsServerEvent } from "@prototype/contracts";
import { ApiError, api } from "../api";
import { demoPlaintext } from "../crypto";
import type { Contact, Session } from "../types";

const WS = import.meta.env.VITE_WS_BASE ?? "ws://localhost:3000";

type SocketMessage = ReturnType<typeof WsServerEvent.parse>;

type UseMessengerSocketOptions = {
	session: Session | null;
	onIncomingMessage: (message: {
		id: string;
		peerId: string;
		from: string;
		text: string;
		direction: "in";
	}) => void;
	onContact: (contact: Contact) => void;
	onTokenRefresh: (session: Session) => void;
	onMalformedMessage: (error: unknown) => void;
	seenEnvelopeIdsRef: MutableRefObject<Set<string>>;
	wsRef: MutableRefObject<WebSocket | null>;
};

function parseSocketMessage(data: string): SocketMessage | null {
	try {
		const parsed = JSON.parse(data);
		const result = WsServerEvent.safeParse(parsed);
		return result.success ? result.data : null;
	} catch {
		return null;
	}
}

export function useMessengerSocket({
	session,
	onIncomingMessage,
	onContact,
	onTokenRefresh,
	onMalformedMessage,
	seenEnvelopeIdsRef,
	wsRef,
}: UseMessengerSocketOptions) {
	const callbacksRef = useRef({ onIncomingMessage, onContact, onTokenRefresh, onMalformedMessage });

	useEffect(() => {
		callbacksRef.current = { onIncomingMessage, onContact, onTokenRefresh, onMalformedMessage };
	}, [onIncomingMessage, onContact, onTokenRefresh, onMalformedMessage]);

	const accessToken = session?.accessToken;
	const refreshToken = session?.refreshToken;

	useEffect(() => {
		if (!accessToken || !refreshToken) return;
		const ws = new WebSocket(`${WS}/v1/ws`, `bearer.${accessToken}`);
		wsRef.current = ws;

		ws.onmessage = async (event) => {
			const data = typeof event.data === "string" ? parseSocketMessage(event.data) : null;
			if (!data) {
				callbacksRef.current.onMalformedMessage(new Error("Malformed websocket message"));
				return;
			}

			if (data.type === "envelope.deliver") {
				const envelope = data.payload;
				if (!seenEnvelopeIdsRef.current.has(envelope.envelopeId)) {
					seenEnvelopeIdsRef.current.add(envelope.envelopeId);
					callbacksRef.current.onIncomingMessage({
						id: envelope.envelopeId,
						peerId: envelope.senderAccountId,
						from: envelope.senderAccountId,
						text: demoPlaintext(envelope.ciphertext),
						direction: "in",
					});
					callbacksRef.current.onContact(envelope.sender);
				}
				ws.send(JSON.stringify({ type: "envelope.ack", payload: { envelopeIds: [envelope.envelopeId] } }));
			}

			if (data.type === "error") {
				callbacksRef.current.onMalformedMessage(new ApiError(data.error.message, data.error.code));
			}

			if (data.type === "token.expiring") {
				const next = await api<Session>("/v1/auth/refresh", {
					method: "POST",
					body: JSON.stringify({ refreshToken }),
				});
				callbacksRef.current.onTokenRefresh(next);
			}
		};

		return () => {
			wsRef.current = null;
			ws.close();
		};
	}, [accessToken, refreshToken, seenEnvelopeIdsRef, wsRef]);
}
