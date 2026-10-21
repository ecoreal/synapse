"""仪表盘渲染层: 把已聚合的数据变成一张**自包含**的 HTML。

设计边界: 这个模块是纯函数, 不读盘、不联网、不看时间(时间从 payload 进)。
这样它既能被穷举测试, 也保证"渲染"永远不会偷偷产生副作用。

为什么坚持自包含: 中转站面板常常开在断网的机器 / 内网跳板机上。
引用任何 CDN、外链字体、外链图片, 到了那种场景就是白屏 ——
一个"看起来很专业但打不开"的仪表盘, 比没有仪表盘更糟。
所以这里一个 <script src> / <link> / @import / url(http 都不许出现,
图表全部用内联 SVG 画。
"""

import html as _html

# 颜色语义和 CLI 里一致: 绿=好, 黄=警告, 红=死, 紫=权限/渠道, 灰=不是站的问题
_CLASS = {
    "ok": "ok", "ok_truncated": "ok", "ok_nonjson": "ok",
    "ok_tool_use": "ok", "cache_passthrough": "ok",
    "rate_limited": "warn", "server_error": "warn", "upstream_400": "warn",
    "waf_blocked": "warn", "tool_call_text": "warn", "cache_miss": "warn",
    "timeout": "dead", "conn_error": "dead", "tool_call_broken": "dead",
    "auth_failed": "auth", "auth_unavailable": "auth", "no_channel": "auth",
    "config_error": "self", "internal_error": "self",
}


def _esc(s):
    return _html.escape("" if s is None else str(s), quote=True)


def _kind_class(kind):
    return _CLASS.get(kind or "", "other")


def _pct(rate):
    return f"{(rate or 0) * 100:.1f}%"


def _bar(rate, cls="ok"):
    w = max(0.0, min(1.0, rate or 0.0)) * 100
    return (f'<span class="bar"><span class="fill {cls}" style="width:{w:.1f}%"></span></span>')


def _spark(vals, w=200, h=34, pad=3, colour="#3fb950"):
    """内联 SVG 折线。0/None 视为"没有测量值", 不画, 也绝不补 0(那会画出一条假谷底)。"""
    pts = [(i, v) for i, v in enumerate(vals) if v]
    if len(pts) < 2:
        return '<span class="muted">数据不足</span>'
    x1 = max(len(vals) - 1, 1)
    ys = [v for _i, v in pts]
    lo, hi = min(ys), max(ys)
    span = (hi - lo) or 1

    def fx(i):
        return pad + (w - 2 * pad) * i / x1

    def fy(v):
        return h - pad - (h - 2 * pad) * (v - lo) / span

    poly = " ".join(f"{fx(i):.1f},{fy(v):.1f}" for i, v in pts)
    dots = "".join(f'<circle cx="{fx(i):.1f}" cy="{fy(v):.1f}" r="1.7"/>' for i, v in pts)
    return (f'<svg class="spark" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" aria-label="延迟趋势 {lo}-{hi}ms">'
            f'<polyline points="{poly}" fill="none" stroke="{colour}" stroke-width="1.6" '
            f'stroke-linejoin="round" stroke-linecap="round"/>'
            f'<g fill="{colour}" opacity=".85">{dots}</g>'
            f'<text x="{pad}" y="9" class="sparktxt">{lo}ms</text>'
            f'<text x="{pad}" y="{h - 1}" class="sparktxt">{hi}ms</text>'
            f'</svg>')


def _tiles(p):
    t = p["totals"]
    rate = p["ok_rate"]
    cls = "ok" if rate >= 0.95 else ("warn" if rate >= 0.80 else "dead")
    items = [
        ("全量报告", f'{p["reports_used"]}', "份" + (f' · {p["unreadable_reports"]} 份损坏' if p["unreadable_reports"] else "")),
        ("总体成功率", _pct(rate), f'{t["ok"]}/{t["samples"]} 次测量', cls),
        ("站 / 模型", f'{len(p["stations"])} / {len(p["targets"])}', ""),
        ("最长连败", f'{p["worst_streak"]}', "轮", "dead" if p["worst_streak"] >= 5 else ""),
        ("Synapse 内部错误", f'{p["internal_errors"]}', "已排除在可用率之外",
         "self" if p["internal_errors"] else ""),
    ]
    out = ['<section class="tiles">']
    for name, value, sub, *rest in items:
        k = rest[0] if rest else ""
        out.append(f'<div class="tile {k}"><div class="tname">{_esc(name)}</div>'
                   f'<div class="tvalue">{_esc(value)}</div>'
                   f'<div class="tsub">{_esc(sub)}</div></div>')
    out.append("</section>")
    return "".join(out)


def _stations(p):
    if not p["stations"]:
        return '<p class="muted">还没有可用的全量体检报告。</p>'
    out = ['<table class="grid"><thead><tr><th>站</th><th>模型</th><th>样本</th>'
           '<th>成功率</th><th>最长连败</th><th>主要失败</th><th>判定</th></tr></thead><tbody>']
    for r in p["stations"]:
        kcls = _kind_class("ok" if r["ok_rate"] >= 0.80 else "timeout")
        why = "、".join(f'{_esc(x["kind"])}×{x["count"]}' for x in r["reasons"][:3]) or "—"
        out.append(
            f'<tr><td class="strong">{_esc(r["target"])}</td><td>{r["models"]}</td>'
            f'<td>{r["samples"]}</td>'
            f'<td class="num">{_pct(r["ok_rate"])} {_bar(r["ok_rate"], kcls)}</td>'
            f'<td class="num">{r["longest_streak"]}</td>'
            f'<td class="why">{why}</td>'
            f'<td><span class="badge {_badge(r["verdict"])}">{_esc(r["verdict"])}</span></td>'
            f'</tr>')
    out.append("</tbody></table>")
    if p["internal_errors"]:
        out.append(f'<p class="fine">🐞 另有 {p["internal_errors"]} 次 Synapse 内部错误, '
                   f'那是本程序的 bug, 已排除在可用率之外(没有算到站方账上)。</p>')
    return "".join(out)


def _badge(verdict):
    return {"稳": "b-ok", "勉强": "b-warn", "不建议": "b-dead"}.get(verdict, "b-gray")


def _heatmap(p):
    rounds = p["rounds"]
    if not rounds or not p["targets"]:
        return (f'<p class="muted">还没有逐轮记录 —— 先跑一次全量体检: '
                f'<code>{_esc(p["cmd"])} check</code></p>')
    # 列太多就只画最近 60 轮(再多屏幕上也看不出差别), 并明说截断了
    shown = rounds[-60:]
    truncated = len(rounds) - len(shown)
    keys = [(r["target"], r["model"]) for r in p["targets"]]
    out = ['<div class="legend">']
    for cls, label in (("ok", "正常"), ("warn", "警告"), ("dead", "失败"),
                       ("auth", "权限/渠道"), ("self", "我方(配置/内部Bug)")):
        out.append(f'<span class="lg"><i class="cell k-{cls}"></i>{label}</span>')
    out.append("</div>")
    out.append('<div class="heatwrap"><table class="heat"><tbody>')
    for t, m in keys:
        name = f"{t}/{m}"
        out.append(f'<tr><th class="hname" title="{_esc(name)}">{_esc(name)}</th><td class="hcells">')
        for rd in shown:
            cell = rd["cells"].get((t, m))
            if cell is None:
                out.append('<i class="cell k-none" data-kind="none"></i>')
            else:
                kind, lat = cell
                tip = f'{rd["label"]} · {kind}' + (f' · {lat}ms' if lat else "")
                # data-kind 保留原始判定: 颜色只是语义归类, 原始 kind 才是证据
                out.append(f'<i class="cell k-{_kind_class(kind)}" '
                           f'data-kind="{_esc(kind)}" title="{_esc(tip)}"></i>')
        out.append("</td></tr>")
    out.append("</tbody></table></div>")
    out.append(f'<p class="fine">左→右 = 旧→新, 每格一轮。'
               f'{f"共 {len(rounds)} 轮, 只画最近 {len(shown)} 轮。" if truncated else ""}'
               f'悬停看当轮判定与延迟。</p>')
    return "".join(out)


def _reasons(p):
    agg = {}
    for r in p["stations"]:
        for x in r["reasons"]:
            agg[x["kind"]] = agg.get(x["kind"], 0) + x["count"]
    if not agg:
        return '<p class="muted">窗口内没有失败记录。</p>'
    top = sorted(agg.items(), key=lambda kv: -kv[1])[:10]
    peak = top[0][1] or 1
    out = ['<table class="bars"><tbody>']
    for kind, n in top:
        out.append(
            f'<tr><td class="bname"><i class="cell k-{_kind_class(kind)}"></i>{_esc(kind)}</td>'
            f'<td class="bwrap">{_bar(n / peak, _kind_class(kind))}</td>'
            f'<td class="num">{n}</td></tr>')
    out.append("</tbody></table>")
    return "".join(out)


def _latency(p):
    rows = [r for r in p["targets"] if r.get("serie")]
    if not rows:
        return '<p class="muted">还没有可画的延迟数据(成功样本不足)。</p>'
    out = ['<table class="grid"><thead><tr><th>目标/模型</th><th>延迟趋势(仅成功轮)</th>'
           '<th>p50</th><th>平均</th></tr></thead><tbody>']
    for r in rows:
        p50 = f'{r["p50_latency_ms"] / 1000:.1f}s' if r["p50_latency_ms"] else "—"
        avg = f'{r["avg_latency_ms"] / 1000:.1f}s' if r["avg_latency_ms"] else "—"
        out.append(f'<tr><td class="strong">{_esc(r["target"])}/{_esc(r["model"])}</td>'
                   f'<td>{_spark(r["serie"])}</td>'
                   f'<td class="num">{p50}</td><td class="num">{avg}</td></tr>')
    out.append("</tbody></table>")
    return "".join(out)


def _issues(p):
    if not p["issues"]:
        return '<p class="muted">没有未解决的问题。</p>'
    out = ['<ul class="issues">']
    for i in p["issues"]:
        who = i["target"] or "-"
        if i.get("model"):
            who += "/" + i["model"]
        out.append(f'<li><span class="iid">#{i["id"]}</span>'
                   f'<span class="badge b-gray">{_esc(i["status"])}</span>'
                   f'<b>{_esc(who)}</b> {_esc(i["symptom"])}'
                   + (f' <span class="muted">({_esc(i["kind"])})</span>' if i.get("kind") else "")
                   + "</li>")
    out.append("</ul>")
    return "".join(out)


_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--muted:#8b949e;
--ok:#3fb950;--warn:#d29922;--dead:#f85149;--auth:#a371f7;--self:#6e7681;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 -apple-system,"Segoe UI","Noto Sans CJK SC","Microsoft YaHei",sans-serif}
header{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:baseline;
padding:18px 22px;border-bottom:1px solid var(--line);
background:linear-gradient(180deg,#161b22,#0d1117)}
.brand{font-size:19px;font-weight:700;letter-spacing:.02em}
.brand .dot{display:inline-block;width:9px;height:9px;border-radius:50%;
background:var(--ok);box-shadow:0 0 10px var(--ok);margin-right:9px;vertical-align:middle}
.brand .ver{font-weight:400;font-size:12px;color:var(--muted);margin-left:6px}
.meta{color:var(--muted);font-size:12.5px}
main{padding:20px 22px 40px;max-width:1180px;margin:0 auto}
section.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:14px 16px;margin:16px 0}
section.panel h2{margin:0 0 12px;font-size:13px;font-weight:600;color:var(--muted);
text-transform:uppercase;letter-spacing:.08em}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:12px;margin:0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;
border-left:3px solid var(--line)}
.tile.ok{border-left-color:var(--ok)}.tile.warn{border-left-color:var(--warn)}
.tile.dead{border-left-color:var(--dead)}.tile.self{border-left-color:var(--self)}
.tname{font-size:11.5px;color:var(--muted);letter-spacing:.04em}
.tvalue{font-size:26px;font-weight:650;font-variant-numeric:tabular-nums;margin:2px 0}
.tsub{font-size:11.5px;color:var(--muted)}
table{border-collapse:collapse;width:100%}
table.grid th{text-align:left;font-size:11.5px;color:var(--muted);font-weight:500;
padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
table.grid td{padding:7px 8px;border-bottom:1px solid #21262d;vertical-align:middle}
table.grid tr:last-child td{border-bottom:0}
td.strong{font-weight:600}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
td.why{color:var(--muted);font-size:12.5px}
td.bname{white-space:nowrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
td.bname .cell{margin-right:7px}
td.bwrap{width:100%}
.bar{display:inline-block;width:76px;height:7px;background:#21262d;border-radius:4px;
overflow:hidden;vertical-align:middle;margin-left:6px}
.bar .fill{display:block;height:100%;border-radius:4px;background:var(--ok)}
.fill.ok{background:var(--ok)}.fill.warn{background:var(--warn)}
.fill.dead{background:var(--dead)}.fill.auth{background:var(--auth)}
.fill.self{background:var(--self)}.fill.other{background:var(--muted)}
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11.5px;
border:1px solid transparent;white-space:nowrap}
.b-ok{color:var(--ok);border-color:#238636;background:#0d2a14}
.b-warn{color:var(--warn);border-color:#9e6a03;background:#2b1d05}
.b-dead{color:var(--dead);border-color:#da3633;background:#2d0f0e}
.b-gray{color:var(--muted);border-color:var(--line);background:#21262d}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-bottom:10px;font-size:12px;color:var(--muted)}
.lg{display:inline-flex;align-items:center;gap:6px}
.cell{display:inline-block;width:11px;height:11px;border-radius:3px;background:#21262d}
.cell.k-ok{background:var(--ok)}.cell.k-warn{background:var(--warn)}
.cell.k-dead{background:var(--dead)}.cell.k-auth{background:var(--auth)}
.cell.k-self{background:var(--self)}.cell.k-other{background:var(--muted)}
.cell.k-none{background:#161b22;box-shadow:inset 0 0 0 1px #21262d}
.heatwrap{overflow-x:auto;padding-bottom:4px}
table.heat td.hcells{display:flex;gap:2px;padding:2px 0}
th.hname{text-align:left;font-weight:500;font-size:12px;padding:2px 10px 2px 0;
white-space:nowrap;color:#c9d1d9;font-family:ui-monospace,Menlo,Consolas,monospace}
.spark{vertical-align:middle}
.sparktxt{fill:#8b949e;font-size:8px;font-family:ui-monospace,monospace}
.muted{color:var(--muted)}
.fine{color:var(--muted);font-size:12px;margin:10px 0 0}
ul.issues{list-style:none;margin:0;padding:0}
ul.issues li{padding:7px 0;border-bottom:1px solid #21262d;font-size:13px}
ul.issues li:last-child{border-bottom:0}
.iid{color:var(--accent);font-variant-numeric:tabular-nums;margin-right:8px;
font-family:ui-monospace,monospace}
ul.issues .badge{margin-right:8px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:0 0 28px}
"""


def render_dashboard(p):
    """p 是聚合好的 dict(见 cmd_report)。返回完整 HTML 字符串, 纯函数。"""
    warn_note = (f' · <span style="color:#d29922">{p["unreadable_reports"]} 份报告损坏(已跳过)</span>'
                 if p["unreadable_reports"] else "")
    body = "".join([
        f'<header><div class="brand"><span class="dot"></span>Synapse'
        f'<span class="ver">v{_esc(p["version"])}</span></div>'
        f'<div class="meta">生成于 {_esc(p["generated"])} · 窗口 {_esc(p["window"])} · '
        f'{p["reports_used"]} 份全量报告{warn_note}</div></header>',
        "<main>",
        _tiles(p),
        f'<section class="panel"><h2>站级记分卡</h2>{_stations(p)}</section>',
        f'<section class="panel"><h2>可用性时间线</h2>{_heatmap(p)}</section>',
        f'<section class="panel"><h2>失败原因分布</h2>{_reasons(p)}</section>',
        f'<section class="panel"><h2>延迟趋势</h2>{_latency(p)}</section>',
        f'<section class="panel"><h2>未解决问题 ({len(p["issues"])})</h2>{_issues(p)}</section>',
        "</main>",
        f'<footer>Synapse v{_esc(p["version"])} · 单文件离线仪表盘, 不含任何外部资源 · '
        f'重新生成: {_esc(p["cmd"])} report</footer>',
    ])
    return (f'<!DOCTYPE html>\n<html lang="zh-CN"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Synapse 体检仪表盘 · {_esc(p["generated"])}</title>'
            f'<style>{_CSS}</style></head><body>{body}</body></html>\n')
