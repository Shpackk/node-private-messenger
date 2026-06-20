import { memo } from "react";

type ToastProps = {
	message: string;
};

export const Toast = memo(function Toast({ message }: ToastProps) {
	if (!message) return null;
	return (
		<div className="toast" role="alert">
			{message}
		</div>
	);
});
