import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 60000,
  retries: 1,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3008',
    headless: true,
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
    { name: 'mobile', use: { browserName: 'chromium', viewport: { width: 375, height: 667 } } },
  ],
  webServer: {
    command: 'echo "Make sure oidc-dev is running: cargo run -p oidc-dev -- start"',
    reuseExistingServer: true,
    timeout: 5000,
  },
});
