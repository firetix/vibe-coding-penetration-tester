#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { chromium } from "playwright";

const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL ?? "http://localhost:3000";
const OUTPUT_DIR =
  process.env.E2E_SCREENSHOT_DIR ??
  "/home/mrachidi/.openclaw/workspace/projects/vibe-pentester/reports/e2e_screenshots";

const STEPS = [
  {
    key: "login",
    targetPath: "/login",
    filename: "01-login-page.png",
  },
  {
    key: "app-scans-redirect",
    targetPath: "/app/scans",
    filename: "02-app-scans-redirected-to-login.png",
    expectUrlIncludes: "/login",
  },
  {
    key: "home",
    targetPath: "/",
    filename: "03-home-page.png",
  },
];

async function run() {
  await fs.mkdir(OUTPUT_DIR, { recursive: true });

  const browser = await chromium.launch({
    headless: true,
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });

  const page = await context.newPage();
  const records = [];

  try {
    for (const step of STEPS) {
      const targetUrl = new URL(step.targetPath, FRONTEND_BASE_URL).toString();
      const screenshotPath = path.join(OUTPUT_DIR, step.filename);

      const response = await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: 20_000,
      });

      if (!response) {
        throw new Error(`No response when navigating to ${targetUrl}`);
      }

      if (step.expectUrlIncludes) {
        await page.waitForURL((url) => url.toString().includes(step.expectUrlIncludes), {
          timeout: 7_000,
        });
      }

      await page.waitForTimeout(1_200);
      await page.screenshot({ path: screenshotPath, fullPage: true });

      records.push({
        step: step.key,
        requestedUrl: targetUrl,
        finalUrl: page.url(),
        status: response.status(),
        screenshotPath,
      });

      console.log(`[ok] ${step.key} -> ${screenshotPath}`);
    }

    console.log("\nScreenshot run summary:");
    console.log(JSON.stringify(records, null, 2));
  } finally {
    await context.close();
    await browser.close();
  }
}

run().catch((error) => {
  console.error("[error] e2e screenshot harness failed");
  console.error(error);
  process.exit(1);
});
