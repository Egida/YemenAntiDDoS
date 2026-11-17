import { describe, it, expect } from 'vitest'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { readFileSync, readdirSync } from 'node:fs'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { join } from 'node:path'
import ts from 'typescript'
import { root } from '../scripts/lib.mjs'

const src = join(root, 'src')

// Full dotted key set of an i18n module by walking its object literal.
function keysOf(file: string): Set<string> {
  const parsed = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
  const keys = new Set<string>()
  const walk = (node: ts.Node, prefix: string): void => {
    if (ts.isObjectLiteralExpression(node)) {
      for (const prop of node.properties) {
        if (!ts.isPropertyAssignment(prop)) { ts.forEachChild(prop, child => walk(child, prefix)); continue }
        const name = ts.isIdentifier(prop.name) ? prop.name.text
          : ts.isStringLiteral(prop.name) ? prop.name.text : null
        if (name === null) { walk(prop.initializer, prefix); continue }
        const full = prefix ? `${prefix}.${name}` : name
        keys.add(full)
        walk(prop.initializer, full)
      }
    } else if (ts.isAsExpression(node) || ts.isParenthesizedExpression(node)) walk(node.expression, prefix)
    else ts.forEachChild(node, child => walk(child, prefix))
  }
  walk(parsed, '')
  return keys
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry: { name: string; isDirectory(): boolean }) => {
    const file = join(dir, entry.name)
    if (entry.isDirectory()) return sourceFiles(file)
    return /\.(vue|ts)$/.test(entry.name) ? [file] : []
  })
}

// Static t('a.b.c') literals in templates/composables. A trailing '.' or '_'
// means the argument is a dynamic prefix (t('audit.' + kind)), not a key.
const usages = sourceFiles(src).flatMap(file => {
  const text = readFileSync(file, 'utf8')
  const keys: string[] = []
  for (const m of text.matchAll(/\bt\(\s*(["'])([A-Za-z0-9_.-]+)\1/g)) {
    const key = m[2]!
    if (key.endsWith('.') || key.endsWith('_')) continue
    keys.push(key)
  }
  return keys.map(key => ({ key, file: file.slice(src.length + 1) }))
})

const en = keysOf(join(src, 'i18n/en.ts'))
const ar = keysOf(join(src, 'i18n/ar.ts'))

describe('i18n', () => {
  it('every static t() key exists in en.ts', () => {
    const missing = usages.filter(u => !en.has(u.key))
    expect(missing.map(u => `${u.file}: ${u.key}`)).toEqual([])
    expect(usages.length).toBeGreaterThan(50)
  })
  it('ar.ts has exactly the en.ts key set', () => {
    expect([...en].filter(k => !ar.has(k))).toEqual([])
    expect([...ar].filter(k => !en.has(k))).toEqual([])
  })
  it('no duplicate full keys within either locale file', () => {
    const dupes = (file: string) => {
      const parsed = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
      const seen = new Set<string>(), duplicate: string[] = []
      const walk = (node: ts.Node, prefix: string): void => {
        if (ts.isObjectLiteralExpression(node)) {
          for (const prop of node.properties) {
            if (!ts.isPropertyAssignment(prop)) { ts.forEachChild(prop, child => walk(child, prefix)); continue }
            const name = ts.isIdentifier(prop.name) ? prop.name.text
              : ts.isStringLiteral(prop.name) ? prop.name.text : null
            if (name !== null) {
              const full = prefix ? `${prefix}.${name}` : name
              // A repeated full key silently overwrites the earlier entry.
              if (seen.has(full)) duplicate.push(full)
              seen.add(full)
              walk(prop.initializer, full)
            } else walk(prop, prefix)
          }
        } else ts.forEachChild(node, child => walk(child, prefix))
      }
      walk(parsed, '')
      return duplicate
    }
    expect(dupes(join(src, 'i18n/en.ts'))).toEqual([])
    expect(dupes(join(src, 'i18n/ar.ts'))).toEqual([])
  })
})
