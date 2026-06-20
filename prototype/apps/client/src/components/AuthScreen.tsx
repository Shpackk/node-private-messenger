import { memo } from "react";
import { QrCode } from "./QrCode";

type AuthScreenProps = {
	username: string;
	password: string;
	mfaRequired: boolean;
	mfaCode: string;
	registrationMfaSetup: { secret: string; otpauthUrl: string } | null;
	registrationMfaCode: string;
	onUsernameChange: (value: string) => void;
	onPasswordChange: (value: string) => void;
	onMfaCodeChange: (value: string) => void;
	onRegistrationMfaCodeChange: (value: string) => void;
	onCopyRegistrationMfaUri: () => void;
	onRegister: () => void;
	onLogin: () => void;
};

export const AuthScreen = memo(function AuthScreen({
	username,
	password,
	mfaRequired,
	mfaCode,
	registrationMfaSetup,
	registrationMfaCode,
	onUsernameChange,
	onPasswordChange,
	onMfaCodeChange,
	onRegistrationMfaCodeChange,
	onCopyRegistrationMfaUri,
	onRegister,
	onLogin,
}: AuthScreenProps) {
	return (
		<main className="auth">
			<section className="auth-panel">
				<h1>Local Messenger</h1>
				<p className="muted">Sign in or create an account to start messaging.</p>
				<div className="stack">
					<input
						placeholder="username"
						value={username}
						onChange={(event) => onUsernameChange(event.target.value)}
					/>
					<input
						placeholder="password"
						type="password"
						value={password}
						onChange={(event) => onPasswordChange(event.target.value)}
					/>
					{mfaRequired && (
						<input
							placeholder="authenticator code"
							inputMode="numeric"
							maxLength={6}
							value={mfaCode}
							onChange={(event) => onMfaCodeChange(event.target.value.replace(/\D/g, "").slice(0, 6))}
						/>
					)}
					<button type="button" onClick={onLogin}>
						{mfaRequired ? "Verify Code" : "Login"}
					</button>
					{!mfaRequired && (
						<>
							{registrationMfaSetup && (
								<div className="secret-box">
									<QrCode value={registrationMfaSetup.otpauthUrl} />
									<small>Scan this QR code before creating the account.</small>
									<button type="button" className="copy-button" onClick={onCopyRegistrationMfaUri}>
										Copy URI
									</button>
									<input
										placeholder="6-digit code"
										inputMode="numeric"
										maxLength={6}
										value={registrationMfaCode}
										onChange={(event) =>
											onRegistrationMfaCodeChange(
												event.target.value.replace(/\D/g, "").slice(0, 6),
											)
										}
									/>
								</div>
							)}
							<button type="button" onClick={onRegister}>
								{registrationMfaSetup ? "Create Account" : "Set Up MFA"}
							</button>
						</>
					)}
				</div>
			</section>
		</main>
	);
});
