import { memo } from "react";

type ComposerProps = {
	activePeerId: string;
	text: string;
	onTextChange: (value: string) => void;
	onSend: () => void;
};

export const Composer = memo(function Composer({ activePeerId, text, onTextChange, onSend }: ComposerProps) {
	const canSend = Boolean(activePeerId && text);

	return (
		<div className="composer">
			<input
				placeholder={activePeerId ? "message" : "discover peer first"}
				value={text}
				onChange={(event) => onTextChange(event.target.value)}
				onKeyDown={(event) => {
					if (event.key === "Enter" && canSend) onSend();
				}}
			/>
			<button type="button" disabled={!canSend} onClick={onSend}>
				Send
			</button>
		</div>
	);
});
