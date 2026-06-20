import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { canonicalEnvelopeBytes } from "@prototype/contracts";
import { ApiError, api } from "./api";
import { AuthScreen } from "./components/AuthScreen";
import { ChatThread } from "./components/ChatThread";
import { Composer } from "./components/Composer";
import { ContactSidebar } from "./components/ContactSidebar";
import { SettingsModal } from "./components/SettingsModal";
import { Toast } from "./components/Toast";
import { demoCiphertext, demoPlaintext, digest, uuid } from "./crypto";
import { useMessengerSocket } from "./hooks/useMessengerSocket";
import {
	ACTIVE_PEER_STORAGE_PREFIX,
	CONTACTS_STORAGE_PREFIX,
	MESSAGES_STORAGE_PREFIX,
	readStored,
} from "./storage";
import type {
	AccountCreateResult,
	AuthChallenge,
	Contact,
	ContactWithLastMessage,
	DiscoveryResult,
	EnvelopeList,
	Message,
	Session,
} from "./types";
import "./style.css";

function App() {
	const [session, setSession] = useState<Session | null>(() => readStored("session", null));
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [peerName, setPeerName] = useState("");
	const [text, setText] = useState("");
	const [activePeerId, setActivePeerId] = useState(() =>
		session ? readStored(`${ACTIVE_PEER_STORAGE_PREFIX}${session.account.accountId}`, "") : "",
	);
	const [messages, setMessages] = useState<Message[]>(() =>
		session ? readStored(`${MESSAGES_STORAGE_PREFIX}${session.account.accountId}`, []) : [],
	);
	const [contacts, setContacts] = useState<Contact[]>(() =>
		session ? readStored(`${CONTACTS_STORAGE_PREFIX}${session.account.accountId}`, []) : [],
	);
	const [settingsOpen, setSettingsOpen] = useState(false);
	const [errorMessage, setErrorMessage] = useState("");
	const wsRef = useRef<WebSocket | null>(null);
	const seenEnvelopeIdsRef = useRef(new Set<string>());

	useEffect(() => {
		if (session) localStorage.setItem("session", JSON.stringify(session));
		else localStorage.removeItem("session");
	}, [session]);

	useEffect(() => {
		if (!session) return;
		localStorage.setItem(`${CONTACTS_STORAGE_PREFIX}${session.account.accountId}`, JSON.stringify(contacts));
	}, [contacts, session]);

	useEffect(() => {
		if (!session) return;
		localStorage.setItem(`${MESSAGES_STORAGE_PREFIX}${session.account.accountId}`, JSON.stringify(messages));
	}, [messages, session]);

	useEffect(() => {
		if (!session) return;
		localStorage.setItem(`${ACTIVE_PEER_STORAGE_PREFIX}${session.account.accountId}`, JSON.stringify(activePeerId));
	}, [activePeerId, session]);

	useEffect(() => {
		if (!errorMessage) return;
		const timeout = window.setTimeout(() => setErrorMessage(""), 5000);
		return () => window.clearTimeout(timeout);
	}, [errorMessage]);

	const addContact = useCallback((contact: Contact) => {
		setContacts((current) => {
			if (current.some((item) => item.accountId === contact.accountId)) {
				return current.map((item) => (item.accountId === contact.accountId ? { ...item, ...contact } : item));
			}
			return [...current, contact];
		});
	}, []);

	const showError = useCallback((error: unknown) => {
		const fallback = "Something went wrong. Try again.";
		if (error instanceof ApiError) {
			const messagesByCode: Record<string, string> = {
				BAD_REQUEST: "Some information is invalid. Check the form and try again.",
				UNAUTHORIZED: "Session expired. Log in again.",
				FORBIDDEN: "You do not have permission to do that.",
				NOT_FOUND: "No matching user was found.",
				USERNAME_TAKEN: "That username is already taken.",
				RECIPIENT_UNAVAILABLE: "That user cannot receive messages right now.",
				QUEUE_FULL: "Recipient inbox is full. Try again later.",
				RATE_LIMITED: "Too many attempts. Wait a moment and try again.",
			};
			setErrorMessage(messagesByCode[error.code ?? ""] ?? error.message ?? fallback);
			return;
		}
		setErrorMessage(error instanceof Error ? error.message : fallback);
	}, []);

	const runAction = useCallback(
		async (action: () => Promise<void>) => {
			try {
				await action();
			} catch (error) {
				showError(error);
			}
		},
		[showError],
	);

	const handleIncomingMessage = useCallback((message: Message) => {
		setMessages((current) => [...current, message]);
	}, []);

	useMessengerSocket({
		session,
		onIncomingMessage: handleIncomingMessage,
		onContact: addContact,
		onTokenRefresh: setSession,
		onMalformedMessage: showError,
		seenEnvelopeIdsRef,
		wsRef,
	});

	const activeContact = useMemo(
		() => contacts.find((contact) => contact.accountId === activePeerId),
		[contacts, activePeerId],
	);

	const threadMessages = useMemo(
		() => messages.filter((message) => message.peerId === activePeerId),
		[messages, activePeerId],
	);

	const contactsWithLastMessage = useMemo<ContactWithLastMessage[]>(() => {
		const lastMessageByPeer = new Map<string, Message>();
		for (let index = messages.length - 1; index >= 0; index -= 1) {
			const message = messages[index];
			if (!lastMessageByPeer.has(message.peerId)) lastMessageByPeer.set(message.peerId, message);
		}
		return contacts.map((contact) => ({
			...contact,
			lastMessage: lastMessageByPeer.get(contact.accountId),
		}));
	}, [contacts, messages]);

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
		setContacts(readStored(`${CONTACTS_STORAGE_PREFIX}${tokens.account.accountId}`, []));
		setMessages(readStored(`${MESSAGES_STORAGE_PREFIX}${tokens.account.accountId}`, []));
		setActivePeerId(readStored(`${ACTIVE_PEER_STORAGE_PREFIX}${tokens.account.accountId}`, ""));
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
		addContact(found);
		setActivePeerId(found.accountId);
		setPeerName("");
	}

	async function send() {
		if (!session || !activePeerId || !text) return;
		const payload = {
			recipientAccountId: activePeerId,
			senderAccountId: session.account.accountId,
			clientMessageId: uuid(),
			ciphertext: demoCiphertext(text),
			ttlSeconds: 3600,
		};
		const signature = await digest(canonicalEnvelopeBytes({ ...payload, signature: "" }));
		const event = { type: "envelope.submit", payload: { ...payload, signature } };
		if (wsRef.current?.readyState === WebSocket.OPEN) {
			wsRef.current.send(JSON.stringify(event));
		} else {
			await api<{ envelopeId: string }>(
				"/v1/envelopes",
				{ method: "POST", body: JSON.stringify(event.payload) },
				session,
			);
		}
		setMessages((current) => [
			...current,
			{
				id: payload.clientMessageId,
				peerId: activePeerId,
				from: session.account.username,
				text,
				direction: "out",
			},
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
				peerId: env.senderAccountId,
				from: env.senderAccountId,
				text: demoPlaintext(env.ciphertext),
				direction: "in" as const,
			})),
		]);
		for (const env of unseen) addContact(env.sender);
		if (leased.envelopes.length) {
			await api(
				"/v1/envelopes/ack",
				{
					method: "POST",
					body: JSON.stringify({ envelopeIds: leased.envelopes.map((env) => env.envelopeId) }),
				},
				currentSession,
			);
		}
	}

	async function setDiscoverable(discoverable: boolean) {
		if (!session) return;
		await api<{ ok: true }>(
			"/v1/discovery",
			{
				method: "PUT",
				body: JSON.stringify({ discoverable }),
			},
			session,
		);
		setSession((current) =>
			current ? { ...current, account: { ...current.account, discoverable } } : current,
		);
	}

	function logout() {
		setSession(null);
		setContacts([]);
		setMessages([]);
		setActivePeerId("");
		setSettingsOpen(false);
	}

	const saveDebugPushToken = () =>
		runAction(async () => {
			if (!session) return;
			await api<{ ok: true }>(
				"/v1/push-token",
				{
					method: "PUT",
					body: JSON.stringify({ platform: "debug", token: `debug-${uuid()}` }),
				},
				session,
			);
		});

	const duressDeleteProbe = () =>
		runAction(async () => {
			if (!session) return;
			await api<{ ok: true }>("/v1/account/duress-delete", {
				method: "POST",
				body: JSON.stringify({
					username: session.account.username,
					password: "duress",
				}),
			});
		});

	if (!session) {
		return (
			<>
				<AuthScreen
					username={username}
					password={password}
					onUsernameChange={setUsername}
					onPasswordChange={setPassword}
					onRegister={() => runAction(register)}
					onLogin={() => runAction(() => login())}
				/>
				<Toast message={errorMessage} />
			</>
		);
	}

	return (
		<main className="messenger">
			<ContactSidebar
				account={session.account}
				peerName={peerName}
				contacts={contactsWithLastMessage}
				activePeerId={activePeerId}
				onPeerNameChange={setPeerName}
				onDiscover={() => runAction(discover)}
				onSelectPeer={setActivePeerId}
				onOpenSettings={() => setSettingsOpen(true)}
				onSaveDebugPushToken={saveDebugPushToken}
				onDuressDeleteProbe={duressDeleteProbe}
			/>
			<section className="chat">
				<ChatThread activeContact={activeContact} messages={threadMessages} />
				<Composer activePeerId={activePeerId} text={text} onTextChange={setText} onSend={() => runAction(send)} />
			</section>
			{settingsOpen && (
				<SettingsModal
					discoverable={session.account.discoverable}
					onClose={() => setSettingsOpen(false)}
					onDiscoverableChange={(value) => runAction(() => setDiscoverable(value))}
					onLogout={logout}
				/>
			)}
			<Toast message={errorMessage} />
		</main>
	);
}

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");
createRoot(root).render(<App />);
