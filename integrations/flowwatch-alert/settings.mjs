/** flowwatch-alert settings —— 监听端口 / 去重窗口 / 卡片时长 / 测试。 */
const vue = globalThis.__CATRACE_VUE__ || {};
const naive = globalThis.__CATRACE_NAIVE__ || {};
const { h, ref, onMounted } = vue;
const { NButton, NInput, NSwitch, useMessage } = naive;

if (typeof h !== 'function' || typeof ref !== 'function') {
  throw new Error('Catrace plugin Vue runtime missing');
}
if (!NButton || !NInput || !NSwitch || !useMessage) {
  throw new Error('Catrace plugin naive runtime missing');
}
if (!plugin || !plugin.config || !plugin.sidecar) {
  throw new Error('Catrace plugin API missing (plugin facade)');
}

const STYLE_ID = 'catrace-plugin-flowwatch-alert-settings-css';
const CSS = `
.fwa-settings { display: flex; flex-direction: column; gap: 1rem; }
.fwa-box { border: 1px solid rgba(127,127,127,.22); border-radius: .5rem;
  padding: .75rem 1rem; display: flex; flex-direction: column; gap: .625rem; }
.fwa-box h3 { margin: 0; font-size: .9375rem; }
.fwa-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.fwa-label { display: flex; flex-direction: column; gap: .125rem; font-size: .875rem; }
.fwa-hint { font-size: .75rem; opacity: .6; }
.fwa-control { min-width: 11rem; display: flex; justify-content: flex-end; }
.fwa-actions { display: flex; gap: .5rem; }
.fwa-status { display: flex; flex-direction: column; gap: .25rem; font-size: .8125rem; }
`;

const DEFAULT_CONFIG = { port: 23457, dedupeSec: 60, cardDurationSec: 0, enabled: true };

function ensureStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = CSS;
  document.head.appendChild(style);
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function errorText(error) {
  return String((error && error.message) || error || '未知错误');
}

function unwrap(result) {
  return result && typeof result === 'object' && 'result' in result ? result.result : result;
}

export default {
  name: 'FlowwatchAlertSettings',
  setup() {
    ensureStyles();
    const message = useMessage();
    const busy = ref('');
    const port = ref(String(DEFAULT_CONFIG.port));
    const dedupeSec = ref(String(DEFAULT_CONFIG.dedupeSec));
    const cardDurationSec = ref(String(DEFAULT_CONFIG.cardDurationSec));
    const enabled = ref(true);
    const status = ref(null);
    let saveTimer = null;

    function currentConfig() {
      return {
        port: clampInt(port.value, 1024, 65535, DEFAULT_CONFIG.port),
        dedupeSec: clampInt(dedupeSec.value, 0, 3600, DEFAULT_CONFIG.dedupeSec),
        cardDurationSec: clampInt(cardDurationSec.value, 0, 3600, DEFAULT_CONFIG.cardDurationSec),
        enabled: enabled.value !== false,
      };
    }

    function applyConfig(cfg) {
      if (!cfg || typeof cfg !== 'object') return;
      port.value = String(clampInt(cfg.port, 1024, 65535, DEFAULT_CONFIG.port));
      dedupeSec.value = String(clampInt(cfg.dedupeSec, 0, 3600, DEFAULT_CONFIG.dedupeSec));
      cardDurationSec.value = String(
        clampInt(cfg.cardDurationSec, 0, 3600, DEFAULT_CONFIG.cardDurationSec),
      );
      enabled.value = cfg.enabled !== false;
    }

    async function persistAndSync({ quiet = false } = {}) {
      const cfg = currentConfig();
      applyConfig(cfg);
      await plugin.config.set(cfg); // ① 落盘：失败直接抛
      try {
        status.value = unwrap(await plugin.sidecar.request('setConfig', cfg)); // ② 推给 sidecar
        if (!quiet) message.success('已保存');
        await plugin.log.info('flowwatch-alert config saved', { cfg });
      } catch (error) {
        if (!quiet) message.warning('已保存（启用插件后生效）');
        await plugin.log.warn('flowwatch-alert config saved without runtime', {
          error: errorText(error),
        });
      }
    }

    function scheduleSave() {
      if (saveTimer) clearTimeout(saveTimer);
      saveTimer = setTimeout(() => {
        saveTimer = null;
        persistAndSync({ quiet: true }).catch((error) => message.error(errorText(error)));
      }, 400);
    }

    async function refreshStatus() {
      try {
        status.value = unwrap(await plugin.sidecar.request('getStatus'));
      } catch {
        status.value = null;
      }
    }

    async function run(key, task) {
      busy.value = key;
      try {
        await task();
      } catch (error) {
        message.error(errorText(error));
      } finally {
        busy.value = '';
      }
    }

    async function testAlert() {
      await run('test', async () => {
        await persistAndSync({ quiet: true });
        const body = unwrap(await plugin.sidecar.request('testAlert'));
        if (body && body.ok && body.deduped) message.warning('已发送，但被去重窗口拦截（未弹卡）');
        else if (body && body.ok) message.success('测试告警已发送');
        else message.error((body && body.error) || '测试失败');
        await refreshStatus();
      });
    }

    onMounted(() => {
      run('boot', async () => {
        const saved = await plugin.config.get();
        if (saved && typeof saved === 'object') applyConfig(saved);
        await persistAndSync({ quiet: true });
      });
    });

    const row = (label, control, hint) =>
      h('div', { class: 'fwa-row' }, [
        h('div', { class: 'fwa-label' }, [
          h('span', null, label),
          hint ? h('span', { class: 'fwa-hint' }, hint) : null,
        ]),
        h('div', { class: 'fwa-control' }, [control]),
      ]);

    const numInput = (r, onChange) =>
      h(NInput, {
        value: r.value,
        'onUpdate:value': (v) => {
          r.value = v;
          onChange();
        },
      });

    return () =>
      h('div', { class: 'fwa-settings' }, [
        h('section', { class: 'fwa-box' }, [
          h('h3', null, '监听'),
          row(
            '启用',
            h(NSwitch, {
              value: enabled.value,
              'onUpdate:value': (v) => {
                enabled.value = v;
                scheduleSave();
              },
            }),
            null,
          ),
          row('端口', numInput(port, scheduleSave), '本机告警入口，默认 23457'),
          row(
            '去重窗口（秒）',
            numInput(dedupeSec, scheduleSave),
            '相同标题在此窗口内只弹一次，0 = 不去重',
          ),
        ]),
        h('section', { class: 'fwa-box' }, [
          h('h3', null, '卡片'),
          row(
            '自动关闭（秒）',
            numInput(cardDurationSec, scheduleSave),
            '0 = 常驻，需手动关闭',
          ),
          h('div', { class: 'fwa-actions' }, [
            h(
              NButton,
              {
                size: 'small',
                type: 'primary',
                secondary: true,
                loading: busy.value === 'test',
                disabled: !!busy.value && busy.value !== 'test',
                onClick: testAlert,
              },
              { default: () => '发送测试告警' },
            ),
            h(
              NButton,
              {
                size: 'small',
                secondary: true,
                loading: busy.value === 'refresh',
                disabled: !!busy.value && busy.value !== 'refresh',
                onClick: () => run('refresh', refreshStatus),
              },
              { default: () => '刷新状态' },
            ),
          ]),
        ]),
        h('section', { class: 'fwa-box' }, [
          h('h3', null, '状态'),
          status.value
            ? h('div', { class: 'fwa-status' }, [
                h('div', null, `运行端口：${status.value.port || '未监听'}`),
                h('div', null, `已发布：${status.value.publishCount || 0} 条`),
                h('div', { class: 'fwa-hint' }, `告警入口：${status.value.alertUrl || '-'}`),
              ])
            : h('div', { class: 'fwa-hint' }, '插件未运行（启用后可见状态）'),
        ]),
      ]);
  },
};
