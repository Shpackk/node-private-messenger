import QRCode from "qrcode";
import { memo, useEffect, useState } from "react";

type QrCodeProps = {
	value: string;
};

export const QrCode = memo(function QrCode({ value }: QrCodeProps) {
	const [src, setSrc] = useState("");

	useEffect(() => {
		let cancelled = false;
		QRCode.toDataURL(value, { errorCorrectionLevel: "M", margin: 2, scale: 6 })
			.then((url) => {
				if (!cancelled) setSrc(url);
			})
			.catch(() => {
				if (!cancelled) setSrc("");
			});
		return () => {
			cancelled = true;
		};
	}, [value]);

	if (!src) return null;
	return <img className="qr-code" src={src} alt="Authenticator setup QR code" />;
});
