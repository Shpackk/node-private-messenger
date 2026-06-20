import { memo, useLayoutEffect, useRef } from "react";
import type { Contact, Message } from "../types";

type ChatThreadProps = {
	activeContact?: Contact;
	messages: Message[];
};

export const ChatThread = memo(function ChatThread({ activeContact, messages }: ChatThreadProps) {
	const latestMessageId = messages.at(-1)?.id;
	const messagesRef = useRef<HTMLDivElement | null>(null);

	useLayoutEffect(() => {
		if (!latestMessageId) return;
		const messagesElement = messagesRef.current;
		if (!messagesElement) return;
		messagesElement.scrollTop = messagesElement.scrollHeight;
	}, [latestMessageId]);

	return (
		<>
			<header className="chat-header">
				<div>
					<h1>{activeContact?.displayName ?? activeContact?.username ?? "Select contact"}</h1>
				</div>
			</header>
			<div className="messages" ref={messagesRef}>
				{messages.length === 0 && (
					<p className="empty">{activeContact ? "No messages yet." : "Discover a peer to start chatting."}</p>
				)}
				{messages.map((message) => (
					<div key={message.id} className={`bubble ${message.direction}`}>
						{message.text}
					</div>
				))}
			</div>
		</>
	);
});
