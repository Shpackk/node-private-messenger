import { readFile } from "node:fs/promises";

const url = process.env.WS_URL;
const tokenFile = process.env.WS_TOKEN_FILE;
const target = Number(process.env.WS_CONNECTIONS ?? "1000");
const holdSeconds = Number(process.env.WS_HOLD_SECONDS ?? "60");

if (!url || !tokenFile) {
	throw new Error("WS_URL and WS_TOKEN_FILE are required");
}

const tokens = (await readFile(tokenFile, "utf8"))
	.split(/\r?\n/)
	.map((value) => value.trim())
	.filter(Boolean);

if (tokens.length < target) {
	throw new Error(`Need ${target} unique account tokens; received ${tokens.length}`);
}

const sockets = [];
let opened = 0;
let failed = 0;
const startedAt = Date.now();

await Promise.all(
	tokens.slice(0, target).map(
		(token) =>
			new Promise((resolve) => {
				const socket = new WebSocket(url, ["messenger.v1", `bearer.${token}`]);
				sockets.push(socket);
				socket.addEventListener(
					"open",
					() => {
						opened += 1;
						resolve();
					},
					{ once: true },
				);
				socket.addEventListener(
					"error",
					() => {
						failed += 1;
						resolve();
					},
					{ once: true },
				);
			}),
	),
);

console.log(
	JSON.stringify({
		event: "load.connected",
		target,
		opened,
		failed,
		connectMs: Date.now() - startedAt,
	}),
);

await new Promise((resolve) => setTimeout(resolve, holdSeconds * 1000));
for (const socket of sockets) socket.close(1000, "load test complete");

if (failed > 0 || opened !== target) process.exitCode = 1;
