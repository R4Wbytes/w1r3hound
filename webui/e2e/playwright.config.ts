import { defineConfig } from "@playwright/test";

// The smoke starts its own hermetic webui (serve-hermetic.sh) in open mode — a
// throwaway repo-root skeleton with an EMPTY login store, so there is no
// sign-in gate and the developer's real webui/auth is never touched. Override
// the URL with W1R3HOUND_UI_URL and set W1R3HOUND_UI_REUSE=1 to point the smoke
// at an already-running console instead of launching its own.
const baseURL = process.env.W1R3HOUND_UI_URL || "http://127.0.0.1:8737";
const reuseOnly = process.env.W1R3HOUND_UI_REUSE === "1";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: "list",
  use: {
    baseURL,
    headless: true,
    // originGuard accepts the loopback Host that Playwright derives from baseURL.
  },
  webServer: reuseOnly
    ? undefined
    : {
        command: "bash ./serve-hermetic.sh",
        url: baseURL + "/api/modules",
        reuseExistingServer: false,
        timeout: 60_000,
        stdout: "pipe",
        stderr: "pipe",
      },
});
