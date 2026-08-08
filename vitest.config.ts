import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
    exclude: ["dist/**", "node_modules/**"],
    coverage: { reporter: ["text", "json", "html"] },
    testTimeout: 30_000,
  },
});
