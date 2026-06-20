import { memo } from "react";
import type { ContactWithLastMessage, Session } from "../types";

type ContactSidebarProps = {
	account: Session["account"];
	peerName: string;
	contacts: ContactWithLastMessage[];
	activePeerId: string;
	onPeerNameChange: (value: string) => void;
	onDiscover: () => void;
	onSelectPeer: (accountId: string) => void;
	onOpenSettings: () => void;
	onSaveDebugPushToken: () => void;
	onDuressDeleteProbe: () => void;
};

export const ContactSidebar = memo(function ContactSidebar({
	account,
	peerName,
	contacts,
	activePeerId,
	onPeerNameChange,
	onDiscover,
	onSelectPeer,
	onOpenSettings,
	onSaveDebugPushToken,
	onDuressDeleteProbe,
}: ContactSidebarProps) {
	return (
		<aside className="contacts">
			<div className="profile-row">
				<div>
					<strong>{account.username}</strong>
					<p className="muted">{account.discoverable ? "Discoverable" : "Hidden"}</p>
				</div>
				<button type="button" className="icon-button" aria-label="Settings" onClick={onOpenSettings}>
					⚙
				</button>
			</div>
			<div className="discover">
				<input
					placeholder="peer username"
					value={peerName}
					onChange={(event) => onPeerNameChange(event.target.value)}
				/>
				<button type="button" onClick={onDiscover}>
					Add
				</button>
			</div>
			<div className="contact-list">
				{contacts.map((contact) => (
					<button
						type="button"
						key={contact.accountId}
						className={`contact ${contact.accountId === activePeerId ? "active" : ""}`}
						onClick={() => onSelectPeer(contact.accountId)}
					>
						<span className="avatar">
							{(contact.displayName ?? contact.username).slice(0, 1).toUpperCase()}
						</span>
						<span className="contact-copy">
							<strong>{contact.displayName ?? contact.username}</strong>
							<span>
								{contact.lastMessage
									? `${contact.lastMessage.direction === "out" ? "You: " : ""}${contact.lastMessage.text}`
									: "No messages yet"}
							</span>
						</span>
					</button>
				))}
			</div>
			<details>
				<summary>Developer</summary>
				<div className="stack">
					<button type="button" className="ghost" onClick={onSaveDebugPushToken}>
						Save Debug Push Token
					</button>
					<button type="button" className="ghost" onClick={onDuressDeleteProbe}>
						Duress Delete Probe
					</button>
				</div>
			</details>
		</aside>
	);
});
