import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		coverage: {
			provider: "v8",
			reporter: ["text", "html"],
		},
		include: ["apps/**/*.test.ts", "packages/contracts/**/*.test.ts"],
		exclude: ["**/node_modules/**", "**/dist/**", "**/cdk.out/**", "**/cdk.*.out/**"],
	},
});
