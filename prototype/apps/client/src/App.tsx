import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { canonicalEnvelopeBytes } from "@prototype/contracts";
import "./style.css";

const API = import.meta.env.VITE_API_BASE ?? "http://localhost:3000";
const WS = import.meta.env.VITE_WS_BASE ?? "ws://localhost:3000";

type Session = {
	account: { accountId: string; username: string };
	accessToken: string;
	refreshToken: string;
};

type Message = { id: string; from: string; text: string; direction: "in" | "out" };
type AccountCreateResult = { username: string };
type AuthChallenge = { challengeId: string };
type DiscoveryResult = { accountId: string };
type QueuedEnvelope = { envelopeId: string; senderAccountId: string; ciphertext: string };
type EnvelopeList = { envelopes: QueuedEnvelope[] };
type EnvelopeDelivery = { envelopeId: string; senderAccountId: string; ciphertext: string };

async function digest(text: string) {
	const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return btoa(String.fromCharCode(...new Uint8Array(bytes)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

function uuid() {
	return crypto.randomUUID();
}

function demoCiphertext(text: string) {
	const body = JSON.stringify({ v: 1, nonce: uuid(), body: btoa(text) });
	return btoa(body).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string) {
	const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
	const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
	return atob(padded);
}

function demoPlaintext(ciphertext: string) {
	try {
		const decoded = JSON.parse(fromBase64Url(ciphertext)) as { body?: string };
		return decoded.body ? atob(decoded.body) : "[could not decrypt demo ciphertext]";
	} catch {
		return "[could not decrypt demo ciphertext]";
	}
}

async function api<T>(path: string, options: RequestInit = {}, session?: Session): Promise<T> {
	const response = await fetch(`${API}${path}`, {
		...options,
		headers: {
			"content-type": "application/json",
			...(session ? { authorization: `Bearer ${session.accessToken}` } : {}),
			...(options.headers ?? {}),
		},
	});
	if (!response.ok) throw new Error((await response.json()).error?.message ?? response.statusText);
	return response.json();
}

function App() {
	const [session, setSession] = useState<Session | null>(() => JSON.parse(localStorage.getItem("session") ?? "null"));
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [peerName, setPeerName] = useState("");
	const [peerId, setPeerId] = useState("");
	const [text, setText] = useState("");
	const [messages, setMessages] = useState<Message[]>([]);
	const [status, setStatus] = useState("offline");
	const wsRef = useRef<WebSocket | null>(null);
	const seenEnvelopeIdsRef = useRef(new Set<string>());

	useEffect(() => {
		if (session) localStorage.setItem("session", JSON.stringify(session));
		else localStorage.removeItem("session");
	}, [session]);

	useEffect(() => {
		if (!session) return;
		const ws = new WebSocket(`${WS}/v1/ws`, `bearer.${session.accessToken}`);
		wsRef.current = ws;
		ws.onopen = () => setStatus("online");
		ws.onclose = () => setStatus("offline");
		ws.onmessage = async (event) => {
			const data = JSON.parse(event.data);
			if (data.type === "envelope.deliver") {
				const envelope = data.payload as EnvelopeDelivery;
				if (!seenEnvelopeIdsRef.current.has(envelope.envelopeId)) {
					seenEnvelopeIdsRef.current.add(envelope.envelopeId);
					setMessages((current) => [
						...current,
						{
							id: envelope.envelopeId,
							from: envelope.senderAccountId,
							text: demoPlaintext(envelope.ciphertext),
							direction: "in",
						},
					]);
				}
				ws.send(JSON.stringify({ type: "envelope.ack", payload: { envelopeIds: [envelope.envelopeId] } }));
				await api<{ acknowledged: number }>(
					"/v1/envelopes/ack",
					{
						method: "POST",
						body: JSON.stringify({ envelopeIds: [envelope.envelopeId] }),
					},
					session,
				).catch(() => undefined);
			}
			if (data.type === "token.expiring") {
				const next = await api<Session>("/v1/auth/refresh", {
					method: "POST",
					body: JSON.stringify({ refreshToken: session.refreshToken }),
				});
				setSession(next);
			}
		};
		return () => ws.close();
	}, [session]);

	const authed = useMemo(() => Boolean(session), [session]);

	async function register() {
		const account = await api<AccountCreateResult>("/v1/accounts", {
			method: "POST",
			body: JSON.stringify({ username, password }),
		});
		await login(account.username);
	}

	async function login(name = username) {
		const challenge = await api<AuthChallenge>("/v1/auth/challenges", {
			method: "POST",
			body: JSON.stringify({ username: name }),
		});
		const tokens = await api<Session>("/v1/auth/verify", {
			method: "POST",
			body: JSON.stringify({ challengeId: challenge.challengeId, username: name, password }),
		});
		setSession(tokens);
		await api<{ ok: true }>(
			"/v1/keys",
			{
				method: "POST",
				body: JSON.stringify({
					identityKey: await digest(`${name}:identity`),
					signedPreKey: await digest(`${name}:signed`),
					signedPreKeySignature: await digest(`${name}:sig`),
					oneTimePreKeys: [await digest(`${name}:one`)],
				}),
			},
			tokens,
		);
		await pullQueued(tokens);
	}

	async function discover() {
		const found = await api<DiscoveryResult>(`/v1/discovery/${peerName}`, {}, session ?? undefined);
		setPeerId(found.accountId);
	}

	async function send() {
		if (!session || !peerId || !text) return;
		const payload = {
			recipientAccountId: peerId,
			senderAccountId: session.account.accountId,
			clientMessageId: uuid(),
			ciphertext: demoCiphertext(text),
			ttlSeconds: 3600,
		};
		const signature = await digest(canonicalEnvelopeBytes({ ...payload, signature: "" }));
		const event = { type: "envelope.submit", payload: { ...payload, signature } };
		if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.send(JSON.stringify(event));
		else
			await api<{ envelopeId: string }>(
				"/v1/envelopes",
				{ method: "POST", body: JSON.stringify(event.payload) },
				session,
			);
		setMessages((current) => [
			...current,
			{ id: payload.clientMessageId, from: session.account.username, text, direction: "out" },
		]);
		setText("");
	}

	async function pullQueued(currentSession = session) {
		if (!currentSession) return;
		const leased = await api<EnvelopeList>("/v1/envelopes", {}, currentSession);
		const unseen = leased.envelopes.filter((env) => !seenEnvelopeIdsRef.current.has(env.envelopeId));
		for (const env of unseen) seenEnvelopeIdsRef.current.add(env.envelopeId);
		setMessages((current) => [
			...current,
			...unseen.map((env) => ({
				id: env.envelopeId,
				from: env.senderAccountId,
				text: demoPlaintext(env.ciphertext),
				direction: "in" as const,
			})),
		]);
		if (leased.envelopes.length)
			await api(
				"/v1/envelopes/ack",
				{
					method: "POST",
					body: JSON.stringify({ envelopeIds: leased.envelopes.map((env) => env.envelopeId) }),
				},
				currentSession,
			);
	}

	return (
		<main>
			<section className="sidebar">
				<h1>Local Messenger</h1>
				<p className="muted">Status: {status}</p>
				{!authed ? (
					<div className="stack">
						<input
							placeholder="username"
							value={username}
							onChange={(event) => setUsername(event.target.value)}
						/>
						<input
							placeholder="password"
							type="password"
							value={password}
							onChange={(event) => setPassword(event.target.value)}
						/>
						<button type="button" onClick={register}>
							Create Account
						</button>
						<button type="button" onClick={() => login()}>
							Login
						</button>
					</div>
				) : (
					<div className="stack">
						<strong>{session?.account.username}</strong>
						<input
							placeholder="peer username"
							value={peerName}
							onChange={(event) => setPeerName(event.target.value)}
						/>
						<button type="button" onClick={discover}>
							Discover
						</button>
						<button
							type="button"
							onClick={() =>
								session &&
								api<{ ok: true }>(
									"/v1/push-token",
									{
										method: "PUT",
										body: JSON.stringify({ platform: "debug", token: `debug-${uuid()}` }),
									},
									session,
								)
							}
						>
							Save Debug Push Token
						</button>
						<details>
							<summary>Developer</summary>
							<button
								type="button"
								onClick={() =>
									session &&
									api<{ ok: true }>("/v1/account/duress-delete", {
										method: "POST",
										body: JSON.stringify({
											username: session.account.username,
											password: "duress",
										}),
									})
								}
							>
								Duress Delete Probe
							</button>
						</details>
						<button type="button" onClick={() => setSession(null)}>
							Logout
						</button>
					</div>
				)}
			</section>
			<section className="chat">
				<div className="messages">
					{messages.map((message) => (
						<div key={message.id} className={`bubble ${message.direction}`}>
							{message.text}
						</div>
					))}
				</div>
				<div className="composer">
					<input
						placeholder={peerId ? "message" : "discover peer first"}
						value={text}
						onChange={(event) => setText(event.target.value)}
					/>
					<button type="button" disabled={!peerId || !text} onClick={send}>
						Send
					</button>
				</div>
			</section>
		</main>
	);
}

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");
createRoot(root).render(<App />);
