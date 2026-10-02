import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts", "parity/**/*.test.ts"],
    environment: "node",
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
