"""synapse_ui — 本地 Web UI(只用标准库): http.server + 内联 HTML/CSS/JS。

分层同其它模块: 这里只做两件事 —— 把数据渲染成界面、把 HTTP 请求翻译成调用。
不读盘、不联网、不自己算业务数字。

数据由调用方注入一个 api 字典:
    snapshot()              -> dict   与 `synapse status --json` 完全相同的一份
    check(target, model)    -> dict
    toggle(name, enabled)   -> dict

为什么要注入而不是 import synapse: 一是避免循环 import(入口在 synapse.py),
二是逼着两个入口用同一份计算 —— 网页和命令行说不一样的话, 用户只会得出
"这工具的数字不可信"。

安全: 只绑 127.0.0.1; 所有请求(包括首页)都要 token, 防止本机其它网页
用 <img src="http://127.0.0.1:PORT/api/target?..."> 这种 CSRF 花招改配置。
"""

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------- 渲染层(纯函数)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def render_app(token, title="Synapse 控制台"):
    """整页自包含: 无外部 <script>/<link>/字体/CDN。断网、离线都能打开。"""
    tok = _esc(token)
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(title)s</title>
<style>
:root{--bg:#0e1116;--panel:#161b22;--line:#21262d;--fg:#e6edf3;--dim:#8b949e;
--ok:#3fb950;--warn:#d29922;--bad:#f85149;--acc:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,"Noto Sans CJK SC","Microsoft YaHei",sans-serif}
header{display:flex;align-items:center;gap:12px;padding:14px 20px;
border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:5}
h1{font-size:16px;margin:0;font-weight:600;letter-spacing:.3px}
.sp{flex:1}
button{font:inherit;color:var(--fg);background:#21262d;border:1px solid #30363d;
border-radius:6px;padding:6px 12px;cursor:pointer}
button:hover{background:#30363d}
button.primary{background:#1f6feb;border-color:#1f6feb}
button.primary:hover{background:#2b7ef5}
button:disabled{opacity:.5;cursor:default}
main{padding:18px 20px 40px;max-width:1180px;margin:0 auto}
.banner{display:flex;gap:14px;align-items:flex-start;padding:14px 16px;border-radius:8px;
background:var(--panel);border-left:4px solid var(--ok);margin-bottom:16px}
.banner.bad{border-left-color:var(--bad)}
.banner.warn{border-left-color:var(--warn)}
.banner b{font-size:15px}
.banner .sub{color:var(--dim);font-size:13px;margin-top:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .k{color:var(--dim);font-size:12px;text-transform:none;letter-spacing:.4px}
.card .v{font-size:20px;font-weight:600;margin-top:6px}
.card .n{color:var(--dim);font-size:12px;margin-top:4px}
h2{font-size:13px;color:var(--dim);font-weight:600;letter-spacing:.5px;
margin:22px 0 8px;text-transform:none}
table{width:100%%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);
font-variant-numeric:tabular-nums;white-space:nowrap}
th{color:var(--dim);font-weight:500;font-size:12px}
tr:last-child td{border-bottom:0}
td.num{text-align:right}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.dim{color:var(--dim)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;
border:1px solid var(--line)}
.pill.on{color:var(--ok);border-color:#238636}
.pill.off{color:var(--dim)}
.iss{padding:8px 10px;border-bottom:1px solid var(--line);display:flex;gap:10px;flex-wrap:wrap}
.iss:last-child{border-bottom:0}
#toast{position:fixed;right:18px;bottom:18px;background:#1f6feb;color:#fff;
padding:10px 14px;border-radius:8px;opacity:0;transition:opacity .2s;pointer-events:none}
#toast.show{opacity:1}
#toast.err{background:#b62324}
.empty{color:var(--dim);padding:12px;background:var(--panel);border:1px solid var(--line);
border-radius:8px}
</style></head><body>
<header>
  <h1>Synapse 控制台</h1>
  <span class="dim" id="stamp"></span>
  <span class="sp"></span>
  <button id="btn-refresh">刷新</button>
  <button id="btn-check" class="primary">立即全量体检</button>
</header>
<main>
  <div id="banner" class="banner"><div><b>读取中…</b></div></div>
  <div class="cards" id="cards"></div>

  <h2>目标清单</h2>
  <div id="targets"></div>

  <h2>长期稳定性（仅全量轮）</h2>
  <div id="uptime"></div>

  <h2>未解决台账</h2>
  <div id="issues"></div>
</main>
<div id="toast"></div>
<script>
const TOK = %(tok)s;
const q = (p) => p + (p.includes('?') ? '&' : '?') + 't=' + encodeURIComponent(TOK);

function toast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'show' + (isErr ? ' err' : '');
  clearTimeout(t._h); t._h = setTimeout(() => { t.className = ''; }, 2600);
}

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  };
  const r = await fetch(q(path), opt);
  const txt = await r.text();
  let data = null; try { data = JSON.parse(txt); } catch (e) {}
  if (!r.ok) throw new Error((data && (data.error || data.detail)) || ('HTTP ' + r.status));
  return data;
}

const pct = (x) => (x === null || x === undefined) ? '—' : (x * 100).toFixed(1) + '%%';
const num = (x) => (x === null || x === undefined) ? '—' : Math.round(x);
const ago = (h) => (h === null || h === undefined) ? '—'
  : (h < 1 ? Math.round(h * 60) + ' 分钟' : (h < 48 ? h.toFixed(1) + ' 小时' : (h / 24).toFixed(1) + ' 天'));

function el(tag, props, kids) {
  const e = document.createElement(tag);
  if (props) for (const k in props) {
    if (k === 'cls') e.className = props[k];
    else if (k === 'text') e.textContent = props[k];
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), props[k]);
    else e.setAttribute(k, props[k]);
  }
  (kids || []).forEach(k => e.appendChild(k));
  return e;
}

function render(d) {
  const v = d.verdict || {};
  document.getElementById('stamp').textContent = d.time || '';

  // 第一屏就是结论
  const b = document.getElementById('banner');
  b.className = 'banner' + (v.failing ? ' bad' : '');
  b.textContent = '';
  if (v.failing && v.worst) {
    const w = v.worst;
    b.appendChild(el('div', {}, [
      el('b', {text: v.failing + ' 个目标/模型正在失败'}),
      el('div', {cls: 'sub',
        text: '最久：' + w.target + '/' + w.model + ' · 连败 ' + w.streak +
              ' 轮 · ' + ago(w.hours) + '没通过' + (w.since ? '（自 ' + w.since + '）' : '')})
    ]));
  } else {
    b.classList.add('');
    b.appendChild(el('div', {}, [
      el('b', {text: '没有正在失败的目标'}),
      el('div', {cls: 'sub', text: '所有被测目标最近一轮都通过了 —— 通过 ≠ 长期稳，看下面的稳定性表'})
    ]));
  }

  // 卡片
  const cards = document.getElementById('cards');
  cards.textContent = '';
  const pick = v.pick, cur = v.current_default, lc = d.last_check, up = d.uptime || {};
  const card = (k, v_, n, cls) => el('div', {cls: 'card'}, [
    el('div', {cls: 'k', text: k}),
    el('div', {cls: 'v ' + (cls || ''), text: v_}),
    el('div', {cls: 'n', text: n || ''})
  ]);
  cards.appendChild(card('推荐（窗口内）',
    pick ? pick.target + '/' + pick.model : '样本不足',
    pick ? pct(pick.ok_rate) + ' · ' + pick.samples + ' 次' : '多跑几轮再问', 'ok'));
  cards.appendChild(card('默认站',
    cur ? cur.target : '—',
    cur ? cur.verdict + ' · ' + pct(cur.ok_rate) + ' · 连败 ' + cur.longest_streak : '',
    cur && cur.mismatch ? 'warn' : ''));
  cards.appendChild(card('最近一次全量体检',
    lc ? String((lc.summary || {}).total || 0) + ' 项' : '无',
    lc ? (lc.time + ' · ' + (lc.age_hours === null ? '时间无法解析' : ago(lc.age_hours) + '前')) : '还没跑过全量 check',
    lc && lc.stale ? 'warn' : ''));
  cards.appendChild(card('未解决台账', String((d.issues || []).length) + ' 项',
    up.reports_used !== undefined ? ('窗口 ' + up.days + ' 天 / ' + up.reports_used + ' 份报告') : ''));

  // 目标清单
  const tg = document.getElementById('targets');
  tg.textContent = '';
  const rowsByTarget = {};
  ((up.targets) || []).forEach(r => {
    const k = r.target; (rowsByTarget[k] = rowsByTarget[k] || []).push(r);
  });
  const t = el('table', {}, [el('thead', {}, [el('tr', {}, [
    '状态', '目标', '模型', '最近一轮', '连败', '通过率', 'p50 延迟', '操作'
  ].map(h => el('th', {text: h})))])]);
  const tb = el('tbody');
  const names = Object.keys(d.targets || {});
  if (!names.length) {
    tg.appendChild(el('div', {cls: 'empty', text: '配置里没有任何目标'}));
  } else {
    names.forEach(name => {
      const e = d.targets[name] || {};
      const on = e.enabled !== false;
      const arr = rowsByTarget[name] || [];
      const r = arr.slice().sort((a, b2) => (b2.streak || 0) - (a.streak || 0))[0];
      const bad = r && r.last_kind && !['ok','ok_truncated','ok_nonjson','ok_tool_use','cache_passthrough'].includes(r.last_kind);
      tb.appendChild(el('tr', {}, [
        el('td', {}, [el('span', {cls: 'pill ' + (on ? 'on' : 'off'), text: on ? '启用' : '已停用'})]),
        el('td', {text: name + (e.default ? ' ★' : '')}),
        el('td', {cls: 'num', text: String((e.models || []).length)}),
        el('td', {cls: bad ? 'bad' : (r ? 'ok' : 'dim'), text: r ? (r.last_kind || '—') : '无数据'}),
        el('td', {cls: 'num' + (r && r.streak ? ' bad' : ''), text: r ? String(r.streak || 0) : '—'}),
        el('td', {cls: 'num', text: r ? pct(r.ok_rate) : '—'}),
        el('td', {cls: 'num', text: r ? num(r.p50_latency_ms) + ' ms' : '—'}),
        el('td', {}, [
          el('button', {text: on ? '停用' : '启用',
            onclick: () => toggle(name, !on)}),
          el('button', {text: '单站体检', style: 'margin-left:6px',
            onclick: (ev) => checkOne(name, ev.target)})
        ])
      ]));
    });
    t.appendChild(tb);
    tg.appendChild(t);
  }

  // 长期稳定性
  const ut = document.getElementById('uptime');
  ut.textContent = '';
  const rows = (up.targets || []).slice().sort((a, b2) => (a.ok_rate === null ? 2 : a.ok_rate) - (b2.ok_rate === null ? 2 : b2.ok_rate));
  if (!rows.length) {
    ut.appendChild(el('div', {cls: 'empty', text: '窗口内还没有全量体检报告 —— 点右上「立即全量体检」攒历史'}));
  } else {
    const t2 = el('table', {}, [el('thead', {}, [el('tr', {}, [
      '目标', '模型', '样本', '通过率', '当前连败', '最长连败', '首次异常', '最近通过', 'p50'
    ].map(h => el('th', {text: h})))])]);
    const tb2 = el('tbody');
    rows.forEach(r => {
      tb2.appendChild(el('tr', {}, [
        el('td', {text: r.target}),
        el('td', {text: r.model}),
        el('td', {cls: 'num', text: String(r.samples)}),
        el('td', {cls: 'num ' + (r.ok_rate >= 0.95 ? 'ok' : (r.ok_rate >= 0.7 ? 'warn' : 'bad')), text: pct(r.ok_rate)}),
        el('td', {cls: 'num' + (r.streak ? ' bad' : ''), text: String(r.streak || 0)}),
        el('td', {cls: 'num', text: String(r.longest_streak || 0)}),
        el('td', {cls: 'dim', text: r.since || '—'}),
        el('td', {cls: 'dim', text: r.last_ok || '—'}),
        el('td', {cls: 'num', text: r.p50_latency_ms ? num(r.p50_latency_ms) + ' ms' : '—'})
      ]));
    });
    t2.appendChild(tb2);
    ut.appendChild(t2);
  }

  // 台账
  const is = document.getElementById('issues');
  is.textContent = '';
  const issues = d.issues || [];
  if (!issues.length) {
    is.appendChild(el('div', {cls: 'empty', text: '没有未解决的问题'}));
  } else {
    const box = el('div', {cls: 'card', style: 'padding:0'});
    issues.slice(0, 40).forEach(it => {
      box.appendChild(el('div', {cls: 'iss'}, [
        el('span', {cls: 'pill', text: it.kind || '?'}),
        el('b', {text: (it.target || '') + '/' + (it.model || '')}),
        el('span', {cls: 'dim', text: (it.detail || '').slice(0, 160)}),
        el('span', {cls: 'dim', text: '×' + (it.count || 1) + ' · 最近 ' + (it.last || it.last_seen || '—')})
      ]));
    });
    is.appendChild(box);
  }
}

async function load() {
  try {
    const d = await api('/api/snapshot');
    render(d);
  } catch (e) {
    document.getElementById('banner').className = 'banner bad';
    document.getElementById('banner').textContent = '读取失败：' + e.message;
  }
}

async function toggle(name, enabled) {
  try {
    const r = await api('/api/target', {name: name, enabled: enabled});
    toast(r.changed ? (name + ' → ' + (enabled ? '启用' : '停用') + '（已备份配置）')
                    : (name + ' 本来就是' + (enabled ? '启用' : '停用')));
    load();
  } catch (e) { toast('操作失败：' + e.message, true); }
}

async function checkOne(name, btn) {
  btn.disabled = true; const old = btn.textContent; btn.textContent = '体检中…';
  try {
    const r = await api('/api/check', {target: name});
    const s = (r.summary || {});
    toast(name + '：合计 ' + (s.total === undefined ? '?' : s.total) + ' 项，异常 ' +
      (s.bad === undefined ? 0 : s.bad) + ' 项', (s.bad || 0) > 0);
    load();
  } catch (e) { toast('体检失败：' + e.message, true); }
  btn.disabled = false; btn.textContent = old;
}

document.getElementById('btn-refresh').onclick = load;
document.getElementById('btn-check').onclick = async (ev) => {
  const btn = ev.target; btn.disabled = true; const old = btn.textContent;
  btn.textContent = '全量体检中…（可能要一两分钟）';
  try {
    const r = await api('/api/check', {});
    const s = (r.summary || {});
    toast('全量体检完成：合计 ' + (s.total === undefined ? '?' : s.total) + ' 项，异常 ' +
      (s.bad === undefined ? 0 : s.bad) + ' 项', (s.bad || 0) > 0);
    load();
  } catch (e) { toast('体检失败：' + e.message, true); }
  btn.disabled = false; btn.textContent = old;
};
load();
setInterval(() => { if (!document.hidden) load(); }, 30000);
</script>
</body></html>
""" % {"title": _esc(title), "tok": json.dumps(tok)}

# ---------------------------------------------------------------- 传输层


def make_handler(api, token, say=None):
    """api: {"snapshot": fn, "check": fn(target, model), "toggle": fn(name, enabled)}"""
    log = say or (lambda m: None)

    class Handler(BaseHTTPRequestHandler):
        server_version = "synapse-ui"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *a):        # 默认每请求打一行, 在 UI 里是噪音
            log("[ui] " + (fmt % a))

        def _ok_token(self, q):
            got = (q.get("t") or [None])[0] or self.headers.get("X-Synapse-Token")
            return got == token

        def _send(self, code, text, ctype="application/json; charset=utf-8"):
            body = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, ensure_ascii=False))

        def _body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            if n <= 0 or n > 1 << 20:
                return {}
            raw = self.rfile.read(n)
            try:
                obj = json.loads(raw.decode("utf-8"))
                return obj if isinstance(obj, dict) else {}
            except (ValueError, UnicodeDecodeError):
                return {}

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if not self._ok_token(q):
                self._json(403, {"error": "缺少或错误的 token —— 用启动时打印的完整 URL 打开"})
                return
            if u.path in ("/", "/index.html"):
                self._send(200, render_app(token), "text/html; charset=utf-8")
                return
            if u.path == "/api/snapshot":
                try:
                    self._json(200, api["snapshot"]())
                except Exception as e:                      # 界面比堆栈更有用
                    log(f"[ui] snapshot 出错: {e!r}")
                    self._json(500, {"error": f"读取状态失败: {e}"})
                return
            self._json(404, {"error": f"没有这个路径: {u.path}"})

        def do_POST(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if not self._ok_token(q):
                self._json(403, {"error": "缺少或错误的 token"})
                return
            body = self._body()
            if u.path == "/api/target":
                name = body.get("name")
                enabled = body.get("enabled")
                if not isinstance(name, str) or not name.strip():
                    self._json(400, {"error": "需要 name"})
                    return
                if not isinstance(enabled, bool):
                    self._json(400, {"error": "enabled 必须是 true/false"})
                    return
                try:
                    self._json(200, api["toggle"](name.strip(), enabled))
                except Exception as e:
                    self._json(400, {"error": str(e)})
                return
            if u.path == "/api/check":
                target = body.get("target")
                model = body.get("model")
                if target is not None and not isinstance(target, str):
                    self._json(400, {"error": "target 必须是字符串"})
                    return
                try:
                    self._json(200, api["check"](target, model))
                except Exception as e:
                    self._json(500, {"error": f"体检失败: {e}"})
                return
            self._json(404, {"error": f"没有这个路径: {u.path}"})

        def do_PUT(self):
            self._json(405, {"error": "只支持 GET / POST"})

        do_DELETE = do_PUT

    return Handler


def make_server(api, token, host="127.0.0.1", port=0):
    """只绑回环地址 —— 这东西手里有你的 key 和体检数据, 不该出现在局域网上。"""
    srv = ThreadingHTTPServer((host, port), make_handler(api, token))
    srv.daemon_threads = True
    url = f"http://{host}:{srv.server_address[1]}/?t={token}"
    return srv, url


class CheckBusy(RuntimeError):
    """同一时刻只允许一轮体检 —— 两轮并发会互相覆盖台账和报告。"""


def locked(fn):
    """把 api 里的函数串行化, 并发调用直接报「正在体检」。"""
    lock = threading.Lock()

    def wrapper(*a, **kw):
        if not lock.acquire(blocking=False):
            raise CheckBusy("上一轮体检还没结束")
        try:
            return fn(*a, **kw)
        finally:
            lock.release()

    return wrapper


def open_browser(url):
    try:
        webbrowser.open(url)
        return True
    except Exception:
        return False
