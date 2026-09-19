/** flowwatch-alert 卡片 UI（纯 Vue render，无 SFC，单文件 Blob 加载）。
 * 协议对齐官方 timer / github-notify：props.event/isHovered；
 * emits close（无参）/ action（裸字符串 actionId，不是对象）。 */
const vue = globalThis.__CATRACE_VUE__ || {};
const { h } = vue;

if (typeof h !== 'function') {
  throw new Error('Catrace plugin Vue runtime missing (__CATRACE_VUE__.h)');
}

const STYLE_ID = 'catrace-plugin-flowwatch-alert-css';
const CSS = `
.fwa-card { display: flex; flex-direction: column; width: 100%; min-height: 0;
  --accent: #d29922; --bg: rgba(210,153,34,.14);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
.fwa-card.lv-error { --accent: #f85149; --bg: rgba(248,81,73,.14); }
.fwa-card.lv-info { --accent: #58a6ff; --bg: rgba(88,166,255,.14); }
.fwa-card.lv-success { --accent: #3fb950; --bg: rgba(63,185,80,.14); }
.fwa-card .hdr { display: flex; align-items: center; justify-content: space-between; gap: .5rem; }
.fwa-card .left { display: flex; align-items: center; gap: .5rem; min-width: 0; }
.fwa-card .dot { flex-shrink: 0; width: .625rem; height: .625rem; border-radius: 999px; background: var(--accent); }
.fwa-card .title { margin: 0; font-size: .9375rem; font-weight: 600; color: inherit;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fwa-card .x { flex-shrink: 0; width: 1.5rem; height: 1.5rem; border: none; background: transparent;
  border-radius: .25rem; color: #94a3b8; font-size: 1.125rem; line-height: 1; cursor: pointer; }
.fwa-card .x:hover { background: var(--bg); color: var(--accent); }
.fwa-card .bar { height: .125rem; border-radius: 999px;
  background: linear-gradient(90deg, var(--accent), transparent);
  transform-origin: left center;
  animation: fwa-card-shrink var(--toast-auto-hide-ms, 30000ms) linear forwards;
  margin: .25rem 0 .5rem; }
.fwa-card .bar.paused { animation-play-state: paused; }
@keyframes fwa-card-shrink { from { transform: scaleX(1); } to { transform: scaleX(0); } }
.fwa-card .body { margin: 0; font-size: .8125rem; line-height: 1.45; color: inherit;
  white-space: pre-wrap; word-break: break-word; }
.fwa-card .acts { display: flex; flex-wrap: wrap; gap: .375rem; margin-top: .625rem; }
.fwa-card .btn { border: none; border-radius: .375rem; padding: .375rem .625rem; font-size: .75rem;
  font-weight: 600; cursor: pointer; font-family: inherit; }
.fwa-card .btn.ghost { background: var(--bg); color: inherit; }
.fwa-card .btn.primary { background: var(--accent); color: #fff; }
.fwa-card .btn:hover { filter: brightness(.97); }
`;

function ensureStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(STYLE_ID)) return;
  const el = document.createElement('style');
  el.id = STYLE_ID;
  el.textContent = CSS;
  document.head.appendChild(el);
}

export default {
  name: 'FlowwatchAlertCard',
  props: {
    event: { type: Object, required: true },
    isHovered: { type: Boolean, default: false },
  },
  emits: ['close', 'action'],
  setup(props, { emit }) {
    ensureStyles();
    return () => {
      const ev = props.event || {};
      const actions = Array.isArray(ev.actions) ? ev.actions : [];
      const level = String(ev.level || 'warning');
      const children = [
        h('div', { class: 'hdr' }, [
          h('div', { class: 'left' }, [
            h('span', { class: 'dot' }),
            h('h2', { class: 'title' }, ev.title || '流量告警'),
          ]),
          h(
            'button',
            {
              class: 'x',
              type: 'button',
              'aria-label': 'Close',
              onClick: () => emit('close'),
            },
            '\u00d7',
          ),
        ]),
      ];
      if (!ev.sticky) {
        children.push(h('div', { class: ['bar', props.isHovered ? 'paused' : ''] }));
      }
      if (ev.body) {
        children.push(h('p', { class: 'body' }, ev.body));
      }
      if (actions.length) {
        children.push(
          h(
            'div',
            { class: 'acts' },
            actions.map((a, i) =>
              h(
                'button',
                {
                  key: a.id,
                  type: 'button',
                  class: ['btn', i === actions.length - 1 ? 'primary' : 'ghost'],
                  onClick: () => emit('action', a.id),
                },
                a.label || a.id,
              ),
            ),
          ),
        );
      }
      return h('div', { class: `fwa-card lv-${level}` }, children);
    };
  },
};
