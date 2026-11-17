<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError, request } from '../../api/client'
import { isAdmin } from '../../auth'
import { notify, notifyWrite } from '../../notifications'
import XSeg from '../../components/XSeg.vue'
import XTip from '../../components/XTip.vue'
import XPill from '../../components/XPill.vue'
import XEmpty from '../../components/XEmpty.vue'
import XConfirm from '../../components/XConfirm.vue'
import XDrawer from '../../components/XDrawer.vue'
import ConnectorDrawer from './ConnectorDrawer.vue'
import { kinds, kindName, deletionHint, testResult } from './data'
import type { Kind, ConnectorRow, LegacyRow, ProbeResult, TestKind } from './data'
import { bgpRoutes, testConnector } from './probe'
const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const panels = reactive(Object.fromEntries(kinds.map(kind => [kind, {
  rows: [] as ConnectorRow[], error: '', loading: true, loaded: false,
}])) as Record<Kind, { rows: ConnectorRow[]; error: string; loading: boolean; loaded: boolean }>)
const legacy = reactive({ rows: [] as LegacyRow[], error: '', loading: true, loaded: false, open: false })
const selected = computed(() => String(route.params.kind || 'all'))
const visible = computed(() => kinds.filter(kind => selected.value === 'all' || selected.value === kind))
const segments = computed(() => {
  const complete = kinds.every(kind => panels[kind].loaded && !panels[kind].error)
  const total = kinds.reduce((n, kind) => n + panels[kind].rows.length, 0)
  return [{ value: 'all', label: t('connectors.all') + (complete ? ` ${total}` : '') }, ...kinds.map(value => ({
    value, label: kindName[value] + (panels[value].loaded && !panels[value].error
      ? ` ${panels[value].rows.length}` : ''),
  }))]
})
let alive = true
const controller = new AbortController()
onUnmounted(() => { alive = false; controller.abort() })
const rawError = (error: unknown) => error instanceof Error ? error.message : String(error)
async function load(kind: Kind | 'legacy') {
  const panel = kind === 'legacy' ? legacy : panels[kind]
  panel.loading = true
  panel.error = ''
  try {
    const rows = await request<ConnectorRow[] & LegacyRow[] | null>(kind === 'legacy'
      ? '/api/webhooks' : `/api/settings/${kind}-connectors`, { signal: controller.signal })
    if (alive) panel.rows = rows ?? []
  } catch (error) {
    if (alive) panel.error = rawError(error)
  } finally {
    if (alive) { panel.loading = false; panel.loaded = true }
  }
}
onMounted(() => { void loadInstance(); for (const kind of [...kinds, 'legacy'] as const) void load(kind) })
const drawer = ref(false)
const drawerKind = ref<Kind>('bgp')
const editing = ref<ConnectorRow>()
function open(kind: Kind, row?: ConnectorRow, event?: MouseEvent) {
  if (event && (event.target as HTMLElement).closest('button,a,[role=alertdialog]')) return
  drawerKind.value = kind
  editing.value = row
  drawer.value = true
}
const columns: Record<Kind, string[]> = {
  bgp: ['id', 'name', 'bgp_asn', 'neighbor_ip', 'neighbor_asn', 'flowspec_enabled'],
  xdrop: ['id', 'name', 'api_url', 'api_key', 'timeout_ms'],
  webhook: ['id', 'name', 'url', 'method', 'global'],
  shell: ['id', 'name', 'command', 'default_args'],
}
const labels: Record<string, string> = { name: 'name', bgp_asn: 'asn', neighbor_ip: 'neighborIp', neighbor_asn: 'neighborAsn',
  flowspec_enabled: 'flowspec',
  api_url: 'apiURL', api_key: 'apiKey', timeout_ms: 'timeout', url: 'url', method: 'method',
  global: 'global', command: 'command', default_args: 'defaultArgs' }
function cell(row: ConnectorRow, key: string) {
  const value = (row as unknown as Record<string, unknown>)[key]
  if (key === 'timeout_ms') return Number(value) > 0 ? value : 10000
  return key === 'global' || key === 'flowspec_enabled'
    ? t(value ? 'connectors.yes' : 'connectors.no') : value
}
const probeable = (kind: Kind, row: ConnectorRow) => kind !== 'bgp' || (row as { enabled?: boolean }).enabled !== false
const rowKey = (kind: Kind, row: ConnectorRow) => `${kind}-${row.id}`
const confirm = ref('')
const deleteMessage = reactive({ title: '', hint: '' })
function confirmDelete(kind: Kind, row: ConnectorRow) {
  deleteMessage.title = ''
  deleteMessage.hint = ''
  confirm.value = rowKey(kind, row)
}
async function remove(kind: Kind, row: ConnectorRow) {
  try {
    await notifyWrite(request(`/api/settings/${kind}-connectors/${row.id}`, { method: 'DELETE' }),
      t('connectors.deleted'))
    if (alive) await load(kind)
  } catch (error) {
    const conflict = error instanceof ApiError && error.status === 409
    deleteMessage.title = t('connectors.' + (conflict ? 'cannotDelete' : 'deleteFailed'), { name: row.name })
    const hint = conflict ? deletionHint(rawError(error)) : ''
    deleteMessage.hint = hint ? t('connectors.' + hint) : ''
    throw error
  }
}
const testing = reactive<Partial<Record<Kind, number>>>({})
const results = reactive<Record<string, ProbeResult>>({})
function showTestResult(kind: TestKind, row: ConnectorRow, result: ProbeResult) {
  if (alive) results[rowKey(kind, row)] = result
  else notify([t('connectors.' + result.key, result.args ?? {}), result.detail].filter(Boolean).join('\n'),
    result.ok ? 'ok' : 'crit', !result.ok)
}
async function test(kind: TestKind, row: ConnectorRow) {
  if (!isAdmin() || testing[kind] !== undefined) return
  testing[kind] = row.id
  delete results[rowKey(kind, row)]
  try {
    const reply = await testConnector(kind, row.id)
    showTestResult(kind, row, testResult(kind, reply))
  } catch (error) {
    showTestResult(kind, row, testResult(kind, undefined, rawError(error)))
  } finally { delete testing[kind] }
}
const routesOpen = ref(false)
const routesName = ref('')
const routesOutput = ref('')
const routesBusy = ref<number>()
const routeErrors = reactive<Record<number, string>>({})

interface BGPInstance { local_asn: number; router_id: string; listen_port: number; rtbh_next_hop: string }
interface BGPPeer { connector_id?: number; name?: string; neighbor_ip?: string; session_up?: boolean }
const instance = reactive({
  loaded: false, loading: true, error: '', saving: false, configured: false, speakerRunning: false,
  restart: '', peers: [] as BGPPeer[], peersError: '',
  form: { local_asn: 65000, router_id: '', listen_port: 179, rtbh_next_hop: '' } as BGPInstance,
})
async function loadInstance() {
  instance.loading = true
  instance.error = ''
  try {
    const [reply, peers] = await Promise.all([
      request<any>('/api/settings/bgp-instance', { signal: controller.signal }),
      request<any>('/api/bgp/peers', { signal: controller.signal }).catch(() => null),
    ])
    if (!alive) return
    instance.configured = !!reply?.configured
    instance.speakerRunning = !!reply?.speaker_running
    const src = reply?.instance ?? {}
    instance.form.local_asn = Number(src.local_asn ?? 65000)
    instance.form.router_id = String(src.router_id ?? '')
    instance.form.listen_port = Number(src.listen_port ?? 179)
    instance.form.rtbh_next_hop = String(src.rtbh_next_hop ?? '')
    if (peers) {
      instance.peers = Array.isArray(peers.peers) ? peers.peers : []
      instance.speakerRunning = peers.speaker_running ?? instance.speakerRunning
      instance.peersError = ''
    }
  } catch (error) { if (alive) instance.error = rawError(error) }
  finally { if (alive) { instance.loading = false; instance.loaded = true } }
}
function instanceCheck() {
  const asn = Number(instance.form.local_asn)
  if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295 || !instance.form.router_id.trim()) return t('connectors.instanceRequired')
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(instance.form.router_id.trim())) return t('connectors.routerIdInvalid')
  const lp = Number(instance.form.listen_port)
  if (!Number.isInteger(lp) || lp < 0 || lp > 65535) return t('connectors.listenPortInvalid')
  const nh = instance.form.rtbh_next_hop.trim()
  if (nh && !/^\S+$/.test(nh)) return t('connectors.rtbhInvalid')
  return ''
}
async function saveInstance() {
  if (instance.saving || !isAdmin()) return
  const msg = instanceCheck()
  if (msg) { instance.error = msg; return }
  instance.saving = true
  instance.error = ''
  instance.restart = ''
  try {
    const body = {
      local_asn: Number(instance.form.local_asn),
      router_id: instance.form.router_id.trim(),
      listen_port: Number(instance.form.listen_port),
      rtbh_next_hop: instance.form.rtbh_next_hop.trim(),
    }
    const reply = await notifyWrite(request<any>('/api/settings/bgp-instance', { method: 'PUT', body: JSON.stringify(body) }), t('connectors.instanceSaved'))
    if (alive) {
      instance.restart = (reply?.restart_required ? t('connectors.restartRequired') : '')
      await loadInstance()
    }
  } catch (error) { if (alive) instance.error = rawError(error) }
  finally { if (alive) instance.saving = false }
}
async function routes(row: ConnectorRow) {
  if (routesBusy.value !== undefined) return
  delete routeErrors[row.id]
  routesOpen.value = false
  routesBusy.value = row.id
  try {
    const reply = await bgpRoutes(row.id)
    if (alive) {
      routesName.value = row.name
      routesOutput.value = reply.output
      routesOpen.value = true
    }
  } catch (error) { if (alive) routeErrors[row.id] = rawError(error) }
  finally { routesBusy.value = undefined }
}
</script>
<template>
  <div class="page cn-page">
    <div class="page-head"><h1>{{ t('nav.connectors') }}</h1></div>
    <XSeg :model-value="selected" :options="segments" :label="t('connectors.type')"
      @update:model-value="router.push($event === 'all' ? '/connectors' : '/connectors/' + $event)" />
    <section v-if="visible.includes('bgp')" class="panel cn-panel cn-instance">
      <div class="panel-head"><h2>{{ t('connectors.instance') }}
        <XTip :text="t('connectors.instanceWhat')" wide /></h2>
        <div class="actions">
          <XPill :tone="instance.configured ? 'ok' : 'neutral'">{{ t('connectors.' + (instance.configured ? 'configured' : 'notConfigured')) }}</XPill>
          <XPill :tone="instance.speakerRunning ? 'ok' : 'neutral'">{{ t('connectors.' + (instance.speakerRunning ? 'speakerRunning' : 'speakerStopped')) }}</XPill>
        </div></div>
      <p v-if="instance.error" class="crit cn-note" role="alert"><span class="mono">{{ instance.error }}</span>
        <button class="btn sm" @click="loadInstance">{{ t('connectors.retry') }}</button></p>
      <XEmpty v-else-if="instance.loading" loading />
      <div v-else class="form cn-form cn-instance-form">
        <div class="cn-grid">
          <label class="field"><span>{{ t('connectors.localAsn') }}</span>
            <input v-model.number="instance.form.local_asn" type="number" min="1" max="4294967295" class="mono" :disabled="!isAdmin() || instance.saving"></label>
          <label class="field"><span>{{ t('connectors.routerId') }}</span>
            <input v-model="instance.form.router_id" class="mono" :disabled="!isAdmin() || instance.saving" placeholder="192.0.2.10"></label>
          <label class="field"><span>{{ t('connectors.listenPort') }} <XTip :text="t('connectors.listenPortTip')" wide /></span>
            <input v-model.number="instance.form.listen_port" type="number" min="0" max="65535" class="mono" :disabled="!isAdmin() || instance.saving"></label>
          <label class="field"><span>{{ t('connectors.rtbhNextHop') }} <XTip :text="t('connectors.rtbhNextHopTip')" wide /></span>
            <input v-model="instance.form.rtbh_next_hop" class="mono" :disabled="!isAdmin() || instance.saving" placeholder="203.0.113.1"></label>
        </div>
        <div class="toolbar">
          <button v-if="isAdmin()" class="btn primary sm" :disabled="instance.saving" @click="saveInstance">{{ t('connectors.' + (instance.saving ? 'saving' : 'save')) }}</button>
          <span v-if="instance.restart" class="ok">{{ instance.restart }}</span>
        </div>
      </div>
      <div v-if="!instance.loading" class="cn-peers">
        <div class="panel-head"><h3>{{ t('connectors.peers') }} <span class="num sub">{{ instance.peers.length }}</span></h3></div>
        <div v-if="instance.peers.length" class="tbl-wrap"><table><thead><tr><th>{{ t('connectors.name') }}</th><th>{{ t('connectors.neighborIp') }}</th><th class="cn-status">{{ t('connectors.status') }}</th></tr></thead>
          <tbody><tr v-for="p in instance.peers" :key="String(p.connector_id)+String(p.neighbor_ip)"><td>{{ p.name || ('#'+(p.connector_id??'')) }}</td><td class="mono">{{ p.neighbor_ip || '' }}</td>
            <td><XPill :tone="p.session_up ? 'ok' : 'neutral'">{{ t('connectors.' + (p.session_up ? 'peerUp' : 'peerDown')) }}</XPill></td></tr></tbody></table></div>
        <p v-else class="sub">{{ t('connectors.noPeers') }}</p>
      </div>
    </section>
    <template v-for="kind in visible" :key="kind">
      <section class="panel cn-panel" :data-kind="kind">
        <div class="panel-head"><h2>{{ kindName[kind] }}
          <span v-if="panels[kind].loaded && !panels[kind].error" class="num sub">{{ panels[kind].rows.length }}</span>
          <XTip :text="t('connectors.' + kind + 'What')" wide /></h2>
          <button v-if="isAdmin()" class="btn sm" @click="open(kind)">{{ t('connectors.add') }}</button></div>
        <div v-if="kind === 'xdrop'" class="cn-note" role="note">
          <strong>{{ t('connectors.decoderScopeTitle') }}</strong><p>{{ t('connectors.decoderScopeBody') }}</p></div>
        <p v-if="panels[kind].error" class="crit cn-note" role="alert">
          <span class="mono">{{ panels[kind].error }}</span>
          <button class="btn sm" @click="load(kind)">{{ t('connectors.retry') }}</button></p>
        <XEmpty v-else-if="panels[kind].loading" loading />
        <div v-else class="tbl-wrap">
          <table><thead><tr><th v-for="key in columns[kind]" :key="key" :class="{ 'cn-id': key === 'id' }">
            {{ key === 'id' ? 'ID' : t('connectors.' + labels[key]) }}
            <XTip v-if="key === 'global'" :text="t('connectors.globalTip')" wide />
          </th><th class="cn-status">{{ t('connectors.status') }}</th>
            <th class="cn-actions">{{ t('connectors.operations') }}</th></tr></thead><tbody>
            <template v-for="row in panels[kind].rows" :key="row.id">
              <tr class="link cn-row" :class="{ 'cn-disabled': !row.enabled }" :data-row="row.id"
                @click="open(kind, row, $event)">
                <td v-for="key in columns[kind]" :key="key" :class="key === 'name' ? '' : 'mono'">
                  <strong v-if="key === 'name'">{{ row.name }}</strong><template v-else>{{ cell(row, key) }}</template>
                </td><td><XPill :tone="row.enabled ? 'ok' : 'neutral'">
                  {{ t('connectors.' + (row.enabled ? 'enabled' : 'disabled')) }}</XPill></td>
                <td><div class="actions">
                  <button v-if="kind !== 'shell' && isAdmin() && probeable(kind, row)" class="btn sm ghost"
                    :disabled="testing[kind] !== undefined" @click="test(kind, row)">
                    {{ t('connectors.' + (testing[kind] === row.id ? 'testing' : 'test')) }}</button>
                  <button v-if="kind === 'bgp' && probeable(kind, row)" class="btn sm ghost"
                    :disabled="routesBusy !== undefined"
                    @click="routes(row)">{{ t('connectors.routes') }}</button>
                  <button v-if="isAdmin()" class="btn sm ghost" @click="confirmDelete(kind, row)">
                    {{ t('connectors.delete') }}</button>
                </div></td>
              </tr>
              <tr v-if="results[rowKey(kind, row)]" class="cn-result"><td :colspan="columns[kind].length + 2">
                <div :class="results[rowKey(kind, row)].ok ? 'ok' : 'crit'">
                  <button class="btn sm ghost cn-close" :aria-label="t('common.close')"
                    @click="delete results[rowKey(kind, row)]">✕</button>
                  {{ results[rowKey(kind, row)].ok ? '✓' : '✕' }}
                  {{ t('connectors.' + results[rowKey(kind, row)].key, results[rowKey(kind, row)].args ?? {}) }}
                  <pre v-if="results[rowKey(kind, row)].detail" class="mono cn-output">
{{ results[rowKey(kind, row)].detail }}</pre>
                </div></td></tr>
              <tr v-if="kind === 'bgp' && routeErrors[row.id]" class="cn-route-error">
                <td :colspan="columns[kind].length + 2"><div class="crit" role="alert">
                  <button class="btn sm ghost cn-close" :aria-label="t('common.close')"
                    @click="delete routeErrors[row.id]">✕</button>
                  {{ t('connectors.fetchRoutesFailed') }}<pre class="mono cn-output">{{ routeErrors[row.id] }}</pre>
                </div></td></tr>
              <tr v-if="confirm === rowKey(kind, row)"><td :colspan="columns[kind].length + 2">
                <XConfirm :model-value="true"
                  :title="t('connectors.deleteConfirm', { kind: kindName[kind], name: row.name })"
                  description="" :action="() => remove(kind, row)" :confirm-label="t('connectors.delete')" tone="danger"
                  @update:model-value="confirm = ''">
                  <p v-if="deleteMessage.title" class="crit">{{ deleteMessage.title }}</p>
                  <p v-if="deleteMessage.hint">{{ deleteMessage.hint }}</p>
                </XConfirm></td></tr>
            </template>
          </tbody></table><XEmpty v-if="!panels[kind].rows.length">{{ t('connectors.empty') }}</XEmpty>
        </div>
      </section>
      <section v-if="kind === 'webhook'" class="panel cn-legacy">
        <div class="panel-head"><h2>{{ t('connectors.legacy') }}
          <span v-if="legacy.loaded && !legacy.error" class="num sub">{{ legacy.rows.length }}</span></h2>
          <button class="btn sm ghost" :aria-expanded="legacy.open" aria-controls="cn-legacy-body"
            @click="legacy.open = !legacy.open">{{ t('connectors.' + (legacy.open ? 'collapse' : 'expand')) }}</button>
        </div>
        <div v-if="legacy.open" id="cn-legacy-body">
          <p class="cn-note" role="note">{{ t('connectors.legacyNote') }}</p>
          <p v-if="legacy.error" class="crit cn-note" role="alert"><span class="mono">{{ legacy.error }}</span>
            <button class="btn sm" @click="load('legacy')">{{ t('connectors.retry') }}</button></p>
          <XEmpty v-else-if="legacy.loading" loading />
          <div v-else class="tbl-wrap"><table><thead><tr><th class="cn-id">ID</th><th>URL</th>
            <th>{{ t('connectors.events') }}</th><th class="cn-status">{{ t('connectors.status') }}</th>
          </tr></thead><tbody><tr v-for="row in legacy.rows" :key="row.id" :class="{ 'cn-disabled': !row.enabled }">
            <td class="mono">{{ row.id }}</td><td class="mono">{{ row.url }}</td>
            <td><div class="actions"><XPill v-for="event in row.events" :key="event">{{ event }}</XPill></div></td>
            <td><XPill :tone="row.enabled ? 'ok' : 'neutral'">
              {{ t('connectors.' + (row.enabled ? 'enabled' : 'disabled')) }}</XPill></td>
          </tr></tbody></table><XEmpty v-if="!legacy.rows.length">{{ t('connectors.empty') }}</XEmpty></div>
        </div>
      </section>
    </template>
    <ConnectorDrawer v-model="drawer" :kind="drawerKind" :row="editing" @saved="load" />
    <XDrawer v-model="routesOpen" :title="t('connectors.bgpRoutes') + ' · ' + routesName" :width="680">
      <pre class="mono cn-output">{{ routesOutput || t('connectors.empty') }}</pre>
      <p class="sub">{{ t('connectors.routesSource') }}</p>
    </XDrawer>
  </div>
</template>
<style scoped>
.cn-page { min-width: 0; }
.cn-page > .seg { margin-bottom: 16px; flex-wrap: wrap; }
.cn-panel, .cn-legacy { margin-bottom: 16px; }
.cn-note { padding: 12px 16px; margin: 0; line-height: 1.7; background: var(--sunk); }
.cn-note p { margin: 6px 0 0; }
.cn-page table { width: 100%; table-layout: fixed; }
.cn-page td { overflow-wrap: anywhere; }
.cn-id { width: 48px; }
.cn-status { width: 92px; }
.cn-actions { width: 194px; }
.cn-disabled { color: var(--muted); }
.cn-disabled strong { font-weight: 400; }
.cn-disabled .pill { color: var(--muted); }
.cn-instance-form { padding: 12px 16px; }
.cn-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
.cn-peers { padding: 0 16px 12px; }
.cn-peers h3 { margin: 8px 0; font-size: 1em; }
.cn-output { max-height: 360px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; margin: 8px 0; }
.cn-close { float: right; }
.cn-result .crit, .cn-route-error .crit { background: var(--tint-crit); padding: 8px; }
@media (max-width: 600px) {
  .cn-page table { min-width: 760px; }
  .cn-page :deep(.tip-text) { position: fixed; left: 16px; top: 30%; width: calc(100vw - 48px); }
}
</style>
