#!/usr/bin/env node
// Runs the test suite gate: every tests/*.test.ts except the entries in
// tests/known-red.txt (pre-arabic-migration debt; see that file's header).
// Fails on stale entries so deletions stay in sync with the filesystem.
import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const listFile = join(root, 'tests', 'known-red.txt')
const knownRed = readFileSync(listFile, 'utf8')
  .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))

const testsDir = join(root, 'tests')
const walk = dir => readdirSync(dir, { withFileTypes: true }).flatMap(e => {
  const file = join(dir, e.name)
  return e.isDirectory() ? walk(file) : /\.test\.ts$/.test(e.name) ? [file] : []
})
const all = walk(testsDir)
const knownSet = new Set(knownRed)
const stale = knownRed.filter(f => !all.includes(join(root, f)))
if (stale.length) {
  console.error('test:gate: stale entries in tests/known-red.txt (file missing):')
  for (const f of stale) console.error('  ' + f)
  process.exit(1)
}
const green = all.filter(f => !knownSet.has(f.slice(root.length + 1)))
  .map(f => f.slice(root.length + 1))
const redPresent = all.filter(f => knownSet.has(f.slice(root.length + 1)))
if (redPresent.length !== knownRed.length) {
  console.error('test:gate: known-red.txt has out-of-tree absolute paths; keep paths relative to console/ like tests/foo.test.ts')
  process.exit(1)
}
console.log(`test:gate: running ${green.length} files (known-red: ${knownRed.length})`)
const res = spawnSync('npx', ['vitest', 'run', ...green], { cwd: root, stdio: 'inherit' })
process.exit(res.status ?? 1)
