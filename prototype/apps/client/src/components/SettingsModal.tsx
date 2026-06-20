import { memo } from "react";

type SettingsModalProps = {
	discoverable: boolean;
	onClose: () => void;
	onDiscoverableChange: (value: boolean) => void;
	onLogout: () => void;
};

export const SettingsModal = memo(function SettingsModal({
	discoverable,
	onClose,
	onDiscoverableChange,
	onLogout,
}: SettingsModalProps) {
	return (
		<div className="modal-backdrop">
			<section className="settings-panel">
				<div className="settings-header">
					<h2>Settings</h2>
					<button type="button" className="ghost" onClick={onClose}>
						Close
					</button>
				</div>
				<label className="toggle-row">
					<span>
						<strong>Discoverable</strong>
						<small>Allow other users to find you by username.</small>
					</span>
					<input type="checkbox" checked={discoverable} onChange={(event) => onDiscoverableChange(event.target.checked)} />
				</label>
				<button type="button" className="danger-button" onClick={onLogout}>
					Logout
				</button>
			</section>
		</div>
	);
});
