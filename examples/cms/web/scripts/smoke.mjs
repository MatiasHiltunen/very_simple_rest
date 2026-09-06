import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';
import { preview } from 'vite';

const output = await mkdtemp(join(tmpdir(), 'vsr-cms-smoke-'));
console.log(`Screenshots: ${output}`);
const server = await preview({ preview: { host: '127.0.0.1', port: 0, open: false } });
const address = server.httpServer.address();
const base = `http://127.0.0.1:${address.port}/studio/`;
let browser;

try {
  browser = await chromium.launch({ headless: true });
  for (const viewport of [
    { width: 1440, height: 1000 },
    { width: 390, height: 844 },
    { width: 850, height: 1000 },
    { width: 1190, height: 1000 },
    { width: 1800, height: 1000 },
    { width: 2100, height: 1200 },
  ]) {
    const page = await browser.newPage({ viewport });
    const errors = [];
    const writes = [];
    const topic = { id: 1, name: 'Engineering', slug: 'engineering', workspace: 1 };
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (path === '/api/auth/login') {
        return route.fulfill({ json: { token: 'browser-smoke-token' } });
      }
      if (path === '/api/auth/account') {
        return route.fulfill({
          json: { id: 1, email: 'editor@example.test', roles: ['admin'], workspace_id: 1 },
        });
      }
      if (request.method() !== 'GET') {
        const body = request.postDataJSON();
        writes.push({ path, body });
        return route.fulfill({ json: { ...body, id: 2 } });
      }
      const items = path === '/api/topics' ? [topic] : path === '/api/workspaces'
        ? [{ id: 1, name: 'Review workspace', slug: 'review', default_locale: 'en' }]
        : [];
      return route.fulfill({ json: { items, total: items.length } });
    });

    await page.goto(base);
    await page.getByLabel('Email address').fill('editor@example.test');
    await page.getByLabel(/^Password/).fill('smoke-test-only');
    await page.getByRole('button', { name: 'Show password' }).click();
    assert.equal(await page.getByLabel(/^Password/).getAttribute('type'), 'text');
    await page.screenshot({ path: join(output, `login-${viewport.width}.png`), fullPage: true });
    await page.getByRole('button', { name: 'Open studio', exact: true }).click();
    await page.getByText('Review workspace', { exact: false }).first().waitFor();

    for (const path of ['topics', 'assets', 'entries', 'users', 'workspaces']) {
      await page.goto(`${base}${path}`);
      await page.locator('.studio-app').waitFor();
      if (path === 'topics') {
        await page.getByLabel('Name', { exact: false }).first().fill('Upgrade smoke');
        await page.getByLabel('Slug', { exact: false }).first().fill('upgrade-smoke');
        await page.getByRole('button', { name: 'Save', exact: true }).click();
        await page.getByText('Topic created successfully.', { exact: true }).waitFor();
        assert(writes.some(({ path, body }) => path === '/api/topics' && body.slug === 'upgrade-smoke'));
      }
      if (path === 'assets') {
        await page.getByLabel('Kind', { exact: false }).first().selectOption('image');
      }
      await page.screenshot({ path: join(output, `${path}-${viewport.width}.png`), fullPage: true });
      const overflow = await page.evaluate(() => [...document.querySelectorAll('body *')]
        .filter((element) => element.getBoundingClientRect().right > window.innerWidth + 1)
        .slice(0, 10).map((element) => ({ tag: element.tagName, className: element.className,
          width: element.getBoundingClientRect().width })));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false,
        `${path} overflows at ${viewport.width}px: ${JSON.stringify(overflow)}`);
    }
    assert.deepEqual(errors, [], `Browser errors at ${viewport.width}px`);
    console.log(`CMS smoke passed at ${viewport.width}x${viewport.height}`);
    await page.close();
  }
} finally {
  await browser?.close();
  await new Promise((resolve, reject) => server.httpServer.close((error) => error ? reject(error) : resolve()));
}
