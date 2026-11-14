import { expect, test } from 'bun:test'

import app, { normalizeTarget } from '../src/worker/index'

const scan = (body: unknown) =>
  app.request('https://trace.test/api/scan-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })

test('bad targets are rejected with JSON before any fetch happens', async () => {
  const bodies = ['null', '[]', '{}', '{', '{"url":42}', '{"url":""}', '{"url":"ftp://example.com"}', '{"url":"https://user:pass@example.com"}', '{"url":"intranet"}']
  for (const body of bodies) {
    const response = await scan(body)
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBeString()
  }
})

test('private and loopback targets are refused', async () => {
  for (const url of ['http://localhost:5189', 'http://127.0.0.1', 'http://10.1.2.3', 'http://192.168.0.5', 'http://169.254.169.254/latest', 'http://172.20.0.1', 'http://[::1]/', 'http://service.internal']) {
    const response = await scan({ url })
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBeString()
  }
})

test('a bare hostname becomes an https target', () => {
  expect(normalizeTarget('example.com/pricing')).toEqual({ url: 'https://example.com/pricing' })
  expect(normalizeTarget('  https://example.com  ')).toEqual({ url: 'https://example.com/' })
  expect(normalizeTarget('example.com/#frag')).toEqual({ url: 'https://example.com/' })
})

test('oversized bodies and unknown API routes never fall through to HTML', async () => {
  const oversized = await app.request('https://trace.test/api/scan-url', { method: 'POST', body: 'x'.repeat(8_000) })
  expect(oversized.status).toBe(413)
  const missing = await app.request('https://trace.test/api/missing')
  expect(missing.status).toBe(404)
  expect((await missing.json()).error).toBeString()
})

test('health check answers JSON', async () => {
  const response = await app.request('https://trace.test/api/health')
  expect(response.status).toBe(200)
  expect(await response.json()).toEqual({ ok: true })
})
