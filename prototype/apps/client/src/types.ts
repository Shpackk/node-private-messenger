export type Session = {
	account: { accountId: string; username: string; displayName: string | null; discoverable: boolean };
	accessToken: string;
	refreshToken: string;
};

export type Contact = { accountId: string; username: string; displayName: string | null };
export type Message = { id: string; peerId: string; from: string; text: string; direction: "in" | "out" };
export type AccountCreateResult = { username: string };
export type AuthChallenge = { challengeId: string };
export type DiscoveryResult = Contact;
export type QueuedEnvelope = { envelopeId: string; senderAccountId: string; sender: Contact; ciphertext: string };
export type EnvelopeList = { envelopes: QueuedEnvelope[] };
export type EnvelopeDelivery = { envelopeId: string; senderAccountId: string; sender: Contact; ciphertext: string };
export type ContactWithLastMessage = Contact & { lastMessage?: Message };
