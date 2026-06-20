import { memo } from "react";

type AuthScreenProps = {
	username: string;
	password: string;
	onUsernameChange: (value: string) => void;
	onPasswordChange: (value: string) => void;
	onRegister: () => void;
	onLogin: () => void;
};

export const AuthScreen = memo(function AuthScreen({
	username,
	password,
	onUsernameChange,
	onPasswordChange,
	onRegister,
	onLogin,
}: AuthScreenProps) {
	return (
		<main className="auth">
			<section className="auth-panel">
				<h1>Local Messenger</h1>
				<p className="muted">Sign in or create an account to start messaging.</p>
				<div className="stack">
					<input placeholder="username" value={username} onChange={(event) => onUsernameChange(event.target.value)} />
					<input
						placeholder="password"
						type="password"
						value={password}
						onChange={(event) => onPasswordChange(event.target.value)}
					/>
					<button type="button" onClick={onLogin}>
						Login
					</button>
					<button type="button" onClick={onRegister}>
						Create Account
					</button>
				</div>
			</section>
		</main>
	);
});
