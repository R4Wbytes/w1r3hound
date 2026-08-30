import { test, expect, ConsoleMessage, Request } from "@playwright/test";

// Dev-only headless smoke for the reskinned SPA (TEST_PLAN.md §3.1/§3.2). It
// guards the strict-CSP-clean load, same-origin asset/API wiring, and the
// five-page navigation. The full scan->SSE->Findings pipeline is validated at
// the API level (webui backend tests) and end-to-end (Juice Shop / loopback).

const CSP_VIOLATION = /Content Security Policy|Refused to (load|execute|apply|connect)/i;

test("dashboard loads with no CSP violations or page errors", async ({ page }) => {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const failedAssets: string[] = [];

  page.on("console", (m: ConsoleMessage) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  page.on("requestfailed", (r: Request) => {
    const u = r.url();
    if (/\.(css|js)(\?|$)/.test(u)) failedAssets.push(u);
  });

  await page.goto("/");
  await expect(page).toHaveTitle(/w1r3hound/i);
  // Sidebar shell rendered — this also proves we are NOT stuck on the sign-in
  // gate (the hermetic server runs in open mode; a stale login-ON server on
  // :8737 would show "Sign in" instead of the sidebar).
  await expect(page.locator(".sidebar-logo-text")).toHaveText(/w1r3hound/i);

  const cspHits = consoleErrors.filter((t) => CSP_VIOLATION.test(t));
  expect(cspHits, `CSP violations in console: ${cspHits.join("\n")}`).toHaveLength(0);
  expect(pageErrors, `page errors: ${pageErrors.join("\n")}`).toHaveLength(0);
  expect(failedAssets, `failed self-hosted assets: ${failedAssets.join("\n")}`).toHaveLength(0);
});

test("navigates all six pages", async ({ page }) => {
  await page.goto("/");
  const pages: Array<[string, string]> = [
    ["overview", "#page-overview"],
    ["audits", "#page-audits"],
    ["findings", "#page-findings"],
    ["console", "#page-console"],
    ["account", "#page-account"],
    ["settings", "#page-settings"],
  ];
  for (const [dataPage, container] of pages) {
    await page.locator(`button.sidebar-nav-item[data-page="${dataPage}"]`).click();
    await expect(page.locator(container)).toHaveClass(/active/);
  }
});

test("serves the module catalog from the same origin (21 modules)", async ({ page }) => {
  await page.goto("/");
  const count = await page.evaluate(async () => {
    const r = await fetch("/api/modules");
    const d = await r.json();
    return (d.modules || []).length;
  });
  expect(count).toBe(21);
});

test("new-scan modal opens and exposes the authorized gate", async ({ page }) => {
  await page.goto("/");
  await page.locator(".js-new-scan").first().click();
  // The target input is the anchor of the modal form.
  await expect(page.locator("#scan-target")).toBeVisible();
  // The mandatory authorization checkbox must be present and default to off.
  const authorized = page.locator("#scan-authorized");
  await expect(authorized).toBeVisible();
  await expect(authorized).not.toBeChecked();
});

test("new-scan modal exposes the CLI-parity advanced options", async ({ page }) => {
  await page.goto("/");
  await page.locator(".js-new-scan").first().click();
  // The advanced options live in a collapsed <details>; open it, then assert
  // the parity controls are wired (Round 14: dir-brute, headers, TLS, egress,
  // resolvers, caps).
  const adv = page.locator("details.adv-section");
  await expect(adv).toBeVisible();
  await adv.locator("summary").click();
  for (const id of [
    "#scan-dir-wordlist",
    "#scan-dir-ext",
    "#scan-headers",
    "#scan-resolver",
    "#scan-resolvers",
    "#scan-wayback",
    "#scan-crawl",
    "#scan-js",
    "#scan-verify-tls",
    "#scan-block-egress",
  ]) {
    await expect(page.locator(id)).toBeVisible();
  }
  // TLS verification defaults OFF (mirrors the CLI's -skip-tls-verify=true).
  await expect(page.locator("#scan-verify-tls")).not.toBeChecked();
});

test("server status LED reports the loopback server as reachable", async ({ page }) => {
  await page.goto("/");
  // app.js pings the backend and flips the LED; give it a moment.
  await expect(page.locator("#server-status-text")).toContainText(/127\.0\.0\.1:8737/);
});
