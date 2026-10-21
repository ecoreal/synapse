#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Synapse — pi 模型连通性定期检查 / 诊断 / 配置修复

原则:
  1. 只对用户在 config.json 里登记的 url+apikey 做只读探测;
  2. 默认绝不修改 ~/.pi/agent/models.json, 只有 `fix --apply`(用户下令)才会写配置;
  3. 所有探测结果落盘到 reports/, 方便追溯。
"""
import argparse
import concurrent.futures as futures
import datetime
import http.client
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
PI_DIR = os.path.expanduser("~/.pi/agent")
PI_MODELS = os.path.join(PI_DIR, "models.json")

__version__ = "1.7.0"


def _init_home():
    """用户数据目录: $SYNAPSE_HOME 或 ~/.config/synapse。
    打包成系统软件后代码在只读的 /usr 下, 数据必须另放。
    兼容老版本(数据跟脚本放一起): 首次运行时把旧数据迁移过去。"""
    default_home = os.path.abspath(os.path.join(os.path.expanduser("~/.config"), "synapse"))
    home = os.path.abspath(os.environ.get("SYNAPSE_HOME") or default_home)
    os.makedirs(home, exist_ok=True)
    # 旧布局迁移: 只对**默认**数据目录做。
    # 显式给了 SYNAPSE_HOME 就是"我就要用这个目录", 不该被塞进项目目录里的旧数据
    # (否则临时目录/沙箱测试会被真实配置污染, 也会误导"空环境"验证)。
    if home != default_home:
        return home
    for fn in ("config.json", "STATIONS.md", "issues.json", ".outage.json",
               ".dirty", ".targets_snapshot.json"):
        src = os.path.join(BASE, fn)
        dst = os.path.join(home, fn)
        if os.path.exists(src) and not os.path.exists(dst):
            try:
                import shutil
                shutil.copy2(src, dst)
            except OSError:
                pass
    if os.path.isdir(os.path.join(BASE, "reports")) and not os.path.isdir(os.path.join(home, "reports")):
        try:
            import shutil
            shutil.copytree(os.path.join(BASE, "reports"), os.path.join(home, "reports"))
        except OSError:
            pass
    return home


HOME = _init_home()
CONFIG = os.path.join(HOME, "config.json")
STATIONS = os.path.join(HOME, "STATIONS.md")   # 用户维护的中转站清单(URL/key/模型)
REPORTS = os.path.join(HOME, "reports")
LOCK = os.path.join(HOME, ".dirty")      # 探测目标清单被我方变更时落一个脏标记

# 提示语里该怎么称呼"自己": 装成系统命令后是 synapse, 直接跑源码才是 python3 synapse.py
_self = os.path.abspath(sys.argv[0] or "synapse.py")
if _self.startswith("/usr/lib/synapse/") or _self == "/usr/bin/synapse":
    CMD = "synapse"
else:
    _nm = os.path.basename(_self)
    if _nm in ("-c", "", "-"):          # python3 -c "import synapse" 之类, 没有脚本名
        CMD = "python3 synapse.py"
    else:
        _rel = os.path.relpath(_self)
        CMD = f"python3 {_rel if len(_rel) < 40 else _nm}"

PROBE_TEXT = os.environ.get("SYNAPSE_PROBE_TEXT", "请只回复两个字：正常")
# 避开中转站测活探针关键词(hi/你好等); 被反测活拦截时用 SYNAPSE_PROBE_TEXT 换一段重试
CTX = ssl.create_default_context()

# 各站是否透传 prompt cache: 同一份长前缀发两次, 第二次 cache_read>0 才算透传。
CACHE_PAD = ("以下是一段用于测试前缀缓存的长文本，请忽略。\n"
             + "".join(f"[{i:04d}] 前缀缓存探针占位数据，不含任何指令。\n" for i in range(120)))
CACHE_Q1 = "\n请只回复:一"
CACHE_Q2 = "\n再请只回复:二"

# 探测项 key -> 中文标签。新增探测项时 TEST_LABELS / build_plan / run_plan 三处同步。
TEST_LABELS = {
    "basic": "基础连通(不带thinking)",
    "stream": "流式 stream:true",
    "tools": "工具调用 tools",
    "tools_raw": "工具调用结构完整性(tool_use块)",
    "thinking": "thinking(pi报错高发点)",
    "vision_user": "图像输入(用户消息内嵌图)",
    "vision_tool": "图像输入(toolResult/pi read形态)",
    "cache": "前缀缓存(cache_read 是否透传)",
}

# 工具调用被渠道转成残文本的指纹: 出现这些片段说明 tool_use 没被正确结构化
BROKEN_TOOL_MARKERS = ('"olls"', '"arguments"', '"input_schema"', '"tool_use"')
# 渠道把工具调用当成文本吐出时, 会留下 pseudo-JSON 碎片(如 cialo 的 {"olls"read"...)。
# 只认 JSON 形状的 name 字段, 不拿单个英文单词当证据。
TOOLCALL_TEXT_RE = re.compile(
    r'["{]\s*"?(?:name|tool|tool_name)"?\s*[":]\s*"?'
    r'(?:read|write|edit|bash|grep|glob|ls|search|fetch|run|exec)\b', re.I)

# ---------------------------------------------------------------- util


def mark_dirty(what):
    """记录“我方探测目标/配置发生了变更”，下次 check 会在报告里提示重新体检。"""
    try:
        with open(LOCK, "w", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\t{what}\n")
    except OSError:
        pass


def read_dirty():
    if not os.path.exists(LOCK):
        return None
    try:
        with open(LOCK, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def clear_dirty():
    try:
        os.remove(LOCK)
    except OSError:
        pass


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, data):
    """原子写 JSON。

    config.json 里是**明文 API key**, 旧实现直接 open(path,'w') 覆盖:
    序列化到一半抛异常(如 data 里有不可序列化对象)、或进程被杀/磁盘满,
    用户就会失去整份配置。现在先写同目录临时文件 + fsync, 再 os.replace
    原子换入 —— 要么是新内容, 要么是旧内容, 不会有半截。
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        chmod_private(tmp)          # 含密钥的文件不给别人读
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):     # 序列化失败/写入失败时清掉半成品
            try:
                os.unlink(tmp)
            except OSError:
                pass


def chmod_private(path):
    try:
        os.chmod(path, 0o600)      # 清单里可能有明文 key，锁权限
    except OSError:
        pass


def load_pi_models():
    d = load_json(PI_MODELS)
    if not d:
        raise SynapseExit(f"[!] 找不到或无法解析 {PI_MODELS}")
    return d


def parse_stations(path=STATIONS):
    """解析 STATIONS.md 里的站清单表格 -> [(name, base_url, key_spec, models, disabled)]。
    - key_spec 支持 `pi:provider名`(引用 pi 配置) 或直接写 sk-xxx
    - 模型列支持逗号/中文逗号/顿号分隔; 写 #off 则标记停用
    """
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        src = f.read()
    begin, end = "<!-- SYNC:BEGIN -->", "<!-- SYNC:END -->"
    if begin in src and end in src:
        src = src.split(begin, 1)[1].split(end, 1)[0]   # 只认表格区，不误读说明表
    rows = []
    for line in src.splitlines():
        line = line.rstrip("\n")
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        name, url, key, models = cells[0], cells[1], cells[2], cells[3]
        if name.strip("`") in ("名字", "Name") or set(name) <= set("-: "):
            continue          # 跳过表头和分隔行
        if name.startswith("<!--") or name.startswith("#"):
            continue
        strip_tick = lambda s: s.strip().strip("`").strip()
        name, url, key, models = map(strip_tick, (name, url, key, models))
        if url.lower() in ("base url", "url"):
            continue          # 说明表格的表头行
        disabled = "#off" in models or "#off" in name
        models = models.replace("#off", "").strip()
        name = name.replace("#off", "").strip()
        if url.startswith("pi:") or key.startswith("pi:"):
            url = ""               # pi: 引用不需要 URL，让 resolve_target 从 pi 取
        ml = [m.strip() for m in re.split(r"[,，、]", models) if m.strip() and m.strip() != "?"]
        rows.append({"name": name, "base_url": url, "key": key,
                     "models": ml, "enabled": not disabled})
    return rows


def stations_to_config(path=STATIONS, say=None):
    """把 STATIONS.md 的表格转成 config.json 结构(不动 pi 的 models.json)。"""
    rows = parse_stations(path)
    if not rows:
        raise SynapseExit(f"[!] 没能从 {path} 解析到任何站，检查表格格式(需 4 列)")
    cfg = {"$comment": "由 synapse.py sync-stations 从 STATIONS.md 生成; 手改会被下次同步覆盖。",
           "targets": {}}
    for r in rows:
        e = {"enabled": r["enabled"]}
        if r["key"].startswith("pi:"):
            e["key_from_pi"] = r["key"][3:].strip()
            if r["base_url"]:
                e["base_url"] = r["base_url"]
        else:
            e["api_key"] = r["key"]
            e["base_url"] = r["base_url"]
            if not r["base_url"] or not r["key"]:
                (say or print)(f"[!] 跳过 {r['name']}: 需 base_url + api_key（或 key 写 pi:provider 复用 pi）")
                continue
        e["models"] = r["models"]
        cfg["targets"][r["name"]] = e
    return cfg


def load_config():
    cfg = load_json(CONFIG)
    if cfg is None:
        raise SynapseExit(f"[!] 缺少 {CONFIG}，先运行: {CMD} import-from-pi")
    return cfg


def resolve_target(cfg, name, api_key=None, base_url=None):
    """返回 (baseUrl, apiKey, models, note)。支持 key_from_pi 引用 pi 配置，避免重复存密钥。"""
    if name:
        entry = cfg["targets"].get(name)
        if entry is None:
            raise SynapseExit(f"[!] config.json 中没有目标: {name}")
    else:
        name = next((k for k, v in cfg["targets"].items() if v.get("default")), None)
        if name is None:
            raise SynapseExit("[!] config.json 中没有标记 default 的目标")
        entry = cfg["targets"][name]
    key = api_key or entry.get("api_key")
    url = base_url or entry.get("base_url")
    if entry.get("key_from_pi"):
        pi = load_json(PI_MODELS, {})
        key = pi.get("providers", {}).get(entry["key_from_pi"], {}).get("apiKey") or key
        url = url or pi.get("providers", {}).get(entry["key_from_pi"], {}).get("baseUrl")
    if not (url and key):
        raise SynapseExit(f"[!] 目标 {name} 缺少 base_url 或 api_key")
    return name, url.rstrip("/"), key, entry


# ---------------------------------------------------------------- probe


def _looks_like_toolcall_text(text):
    """渠道把 tool_use 吐成文本的判据: **必须看到 JSON 碎片**。

    旧实现用 `"read" in text` / 去引号后的 `arguments in text`,
    结果正文里出现 “I have already read the file” 或
    “pass the arguments” 就把好好的站判成工具链路损坏(❌)。
    宁可漏报(归为 tool_call_text 已足够提示), 也不能误报弃用一个正常的站。
    """
    if any(mk in text for mk in BROKEN_TOOL_MARKERS):   # 保留引号, 严格匹配
        return True
    return bool(TOOLCALL_TEXT_RE.search(text))


def _judge_tool_resp(kind, j, raw, snippet):
    """带 tools 的探测: 看响应里到底是合规的 tool_use 块还是渠道吐出来的残文本。"""
    blocks = j.get("content") or []
    has_tool = any(isinstance(b, dict) and b.get("type") == "tool_use" for b in blocks)
    has_text = any(isinstance(b, dict) and b.get("type") == "text" for b in blocks)
    if has_tool:
        return "ok_tool_use", snippet
    if has_text:
        text = " ".join(b.get("text", "") for b in blocks
                         if isinstance(b, dict) and b.get("type") == "text")
        if _looks_like_toolcall_text(text):
            return "tool_call_broken", text[:220]
        return "tool_call_text", text[:220]
    return kind, snippet


def probe(url, key, model, thinking=False, tools=False, stream=False, timeout=60,
          image=False, image_form="user", use_real_image=None):
    """对 /v1/messages 做一次真实探测，返回结构化结果。"""
    body = {
        "model": model,
        "max_tokens": 1024 if thinking else 64,
        "messages": [{"role": "user", "content": PROBE_TEXT}],
    }
    if thinking:
        body["thinking"] = {"type": "enabled", "budget_tokens": 512}
    if tools:
        body["tools"] = [{
            "name": "bash", "description": "Execute a bash command",
            "input_schema": {"type": "object",
                             "properties": {"command": {"type": "string"}},
                             "required": ["command"]},
        }]
    if stream:
        body["stream"] = True
    if image:
        import base64, io
        try:
            from PIL import Image
            im = Image.new("RGB", (64, 64), (30, 144, 255))
            buf = io.BytesIO(); im.save(buf, "PNG")
            b64 = base64.b64encode(buf.getvalue()).decode()
        except ImportError:
            import zlib, struct
            def chunk(t, d):
                c = t + d
                return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c))
            raw = b"".join(b"\x00" + b"\x1e\x90\xff" * 64 for _ in range(64))
            png = (b"\x89PNG\r\n\x1a\n"
                   + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0))
                   + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
            b64 = base64.b64encode(png).decode()
        img = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b64}}
        if use_real_image:
            try:
                with open(use_real_image, "rb") as fh:
                    real = fh.read()
                ext = os.path.splitext(use_real_image)[1].lower()
                mt = {".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                      ".webp": "image/webp", ".gif": "image/gif"}.get(ext, "image/png")
                b64 = base64.b64encode(real).decode()
                img = {"type": "image", "source": {"type": "base64",
                                                  "media_type": mt, "data": b64}}
            except OSError:
                pass  # 读图失败就静默回退内置色块
        if image_form == "tool":
            # pi read 工具的真实形态: 图片经 tool_result 回传
            body["tools"] = [{"name": "read", "description": "read file",
                              "input_schema": {"type": "object",
                                               "properties": {"path": {"type": "string"}}}}]
            body["max_tokens"] = 128
            body["messages"] = [
                {"role": "user", "content": [{"type": "text", "text": "说出图里颜色"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1",
                                                   "name": "read", "input": {"path": "x.png"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                              "content": [img]}]},
            ]
        else:
            body["messages"][0]["content"] = [
                {"type": "text", "text": "这张图是什么颜色？只回答颜色"}, img,
            ]
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{url}/v1/messages", data=data, method="POST",
        headers={"x-api-key": key, "authorization": f"Bearer {key}",
                 "anthropic-version": "2023-06-01", "content-type": "application/json",
                 "user-agent": "curl/8.5.0"},  # 部分站点Cloudflare封python-urllib UA
    )
    t0 = time.time()
    kind, http, snippet = "ok", 0, ""
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
            http = resp.status
            raw = resp.read(3000).decode("utf-8", "replace")
        snippet = raw[:220]
        try:
            j = json.loads(raw)
            stop = j.get("stop_reason")
            if stop == "max_tokens":
                kind = "ok_truncated"
            if tools:
                kind, snippet = _judge_tool_resp(kind, j, raw, snippet)
        except (ValueError, TypeError, AttributeError):
            # 只兜"响应不是我们期望的 JSON 形状": 非 JSON(ValueError)、
            # 顶层不是对象(AttributeError)、字段类型不对(TypeError)。
            # _judge_tool_resp 里的 bug 会冒到外层 → internal_error, 不再被吞。
            kind = "ok_nonjson"
            low = raw.lower()
            if tools and (_looks_like_toolcall_text(raw)):
                kind, snippet = "tool_call_broken", raw[:220]
    except urllib.error.HTTPError as e:
        http = e.code
        raw = e.read(2000).decode("utf-8", "replace")
        snippet = raw[:220]
        kind = classify(http, raw, thinking)
    except Exception as e:                  # noqa: BLE001 —— 单条探针不该炸掉整轮
        kind, snippet = _net_or_internal(e)
    return {"kind": kind, "http": http, "latency_ms": int((time.time() - t0) * 1000),
            "snippet": snippet.replace("\n", " ")}


def probe_multi(url, key, model, prompts, timeout=60, tools=False):
    """同一渠道连发多轮（共用前缀），用于验证 prompt cache 是否透传。
    prompts: [str, ...]  返回 [{kind,http,latency_ms,snippet,usage,text}]
    """
    body = {
        "model": model, "max_tokens": 32,
        "tools": [{"name": "bash", "description": "Execute a bash command",
                   "input_schema": {"type": "object",
                                    "properties": {"command": {"type": "string"}},
                   "required": ["command"]}}] if tools else None,
    }
    out = []
    for text in prompts:
        b = dict(body)
        if b["tools"] is None:
            b.pop("tools")
        b["messages"] = [{"role": "user", "content": text}]
        req = urllib.request.Request(
            f"{url}/v1/messages", data=json.dumps(b).encode(), method="POST",
            headers={"x-api-key": key, "authorization": f"Bearer {key}",
                     "anthropic-version": "2023-06-01", "content-type": "application/json",
                     "user-agent": "curl/8.5.0"})
        t0 = time.time()
        kind, http, snippet, usage, text_out = "ok", 0, "", {}, ""
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
                http = resp.status
                raw = resp.read(4000).decode("utf-8", "replace")
            snippet = raw[:220]
            try:
                j = json.loads(raw)
                usage = j.get("usage") or {}
                blocks = j.get("content") or []
                text_out = " ".join(x.get("text", "") for x in blocks
                                    if isinstance(x, dict) and x.get("type") == "text")
                if j.get("stop_reason") == "max_tokens":
                    kind = "ok_truncated"
            except (ValueError, TypeError, AttributeError):
                kind = "ok_nonjson"
        except urllib.error.HTTPError as e:
            http = e.code
            raw = e.read(2000).decode("utf-8", "replace")
            snippet = raw[:220]
            kind = classify(http, raw, False)
        except Exception as e:             # noqa: BLE001
            kind, snippet = _net_or_internal(e)
        out.append({"kind": kind, "http": http, "snippet": snippet.replace("\n", " "),
                    "usage": usage, "text": text_out,
                    "latency_ms": int((time.time() - t0) * 1000)})
    return out


# WAF/CDN 拦截页指纹(403 不等于 key 错: 很多站返回 HTML 拦截页)
WAF_MARKERS = (
    "访问已被拦截", "访问被拦截", "访问受限", "请求被拦截", "该页面无法访问",
    "just a moment", "attention required", "cloudflare", "cf-error",
    "error code: 1010", "captcha", "safeline", "waf", "request blocked",
    "blocked by", "incapsula", "akamai",
)
# 模型名/分组无渠道的指纹(不是真的上游崩了)
NO_CHANNEL_MARKERS = (
    "无可用渠道", "无可用分组", "没有可用渠道", "model_not_found",
    "model not found", "no available channel", "unknown model",
    "does not exist", "invalid model", "模型不存在",
)


def _looks_html(raw):
    """响应体像网页而不是 API JSON → 基本就是网关/拦截页。"""
    s = raw.lstrip()[:300].lower()
    return s.startswith("<!doctype") or s.startswith("<html") or "<head>" in s \
        or "<title>" in s


def classify(http, raw, thinking_sent):
    """按证据强弱判种类。顺序很关键:
    WAF/拦截页 > 无渠道 > 反测活 > 鉴权 > thinking > 参数 > 限流 > 5xx。
    早期版本把 401/403 放在最前, 导致 HTML 拦截页被误报"key无效/欠费",
    用户会白去换 key。现在先看响应体证据, 再看状态码。"""
    low = raw.lower()
    # 1) WAF/CDN 拦截: 指纹命中, 或 4xx 返回网页(API 不可能返回 HTML 正常体)
    if any(m in low for m in WAF_MARKERS) or (http >= 400 and _looks_html(raw)):
        return "waf_blocked"
    # 2) 模型名/分组没渠道: 503 里也可能带这个, 不能笼统算 5xx
    if any(m in low for m in NO_CHANNEL_MARKERS):
        return "no_channel"
    if "测活" in raw or "探针" in raw or "anti_probe" in low:
        return "anti_probe"
    # 3) 真鉴权问题: 状态码 + 不是网页(前面已排除)
    if http in (401, 403):
        return "auth_failed"
    if http == 503 and "auth_unavailable" in low:
        return "auth_unavailable"
    if http == 400 and "upstream" in low:
        return "thinking_unsupported" if thinking_sent else "upstream_400"
    if http == 400:
        return "bad_request"
    if http == 429:
        return "rate_limited"
    if http >= 500:
        return "server_error"
    return f"http_{http}"


VERDICT = {
    "ok": "✅ 正常",
    "ok_truncated": "✅ 正常(回复被max_tokens截断,无碍)",
    "ok_nonjson": "✅ 通了但响应不是JSON",
    "ok_tool_use": "✅ 工具调用正常(合规 tool_use 块)",
    "tool_call_text": "⚠️ 模型把工具调用写成了文本(claude能自己纠正,但说明渠道转译可疑)",
    "tool_call_broken": "❌ 工具调用被渠道破坏: 吐成坏JSON文本 → 这种站不能做agent任务(只适合纯聊天)",
    "cache_passthrough": "✅ 前缀缓存透传(cache_read>0, 省钱)",
    "cache_miss": "⚠️ 前缀缓存不传(cache_read=0) → pi 每轮全价重算, 这正是 issue#3",
    "auth_failed": "❌ 鉴权失败: key无效或欠费",
    "waf_blocked": "⚠️ 被Cloudflare/WAF拦截(返回拦截网页,非key问题;pi实际请求若也拦截则需换出口)",
    "no_channel": "❌ 模型名在该分组下无可用渠道",
    "anti_probe": "⚠️ 被反测活拦截(探测文案命中关键词, 用 SYNAPSE_PROBE_TEXT 换一段)",
    "thinking_unsupported": "❌ 渠道不支持thinking参数 → 把pi里该模型 reasoning 设为 false",
    "upstream_400": "⚠️ 上游400(参数兼容性问题,跑 diagnose 看细节)",
    "bad_request": "❌ 请求被拒(400,渠道不认这个参数/字段)",
    "auth_unavailable": "❌ 站侧无可用上游(auth_unavailable, 渠道侧账号掉了/欠费)",
    "rate_limited": "⚠️ 限流(429),稍后重试",
    "server_error": "⚠️ 上游5xx,渠道不稳",
    "timeout": "❌ 超时",
    "conn_error": "❌ 连接失败(DNS/网络/TLS)",
    "config_error": "❌ 目标配置不完整(缺 base_url/api_key) → 该站本轮根本没被检查",
    # 这一条永远不该出现在正常报告里; 出现就说明是 Synapse 自己的 bug, 别去折腾中转站。
    "internal_error": "🐞 Synapse 内部错误(不是站的问题!) → 这是本程序的 bug, 请带着这一行提 issue",
}

# 网络层可预期异常。只有这些才配被解释成"站方/链路有问题"。
# 其它异常(_net_or_internal 会判成 internal_error)一律是我们自己的 bug:
# 旧实现 catch Exception 全算 conn_error, 我们自己的 KeyError 会被报成"站连不上",
# 用户就去追一个本该健康的站 —— 这是最坏的一种假阳性。
NET_ERRORS = (urllib.error.URLError, TimeoutError, ssl.SSLError,
              http.client.HTTPException, OSError)


def _net_or_internal(e):
    """异常分诊: 网络问题 → timeout/conn_error; 我们自己的 bug → internal_error。

    注意不吞异常语义: 这里只是给异常**贴标签**, 不是掩盖。internal_error 会
    在报告里显眼地标成"不是站的问题", 并让整轮检查算异常(退出码 1)。
    """
    snip = f"{type(e).__name__}: {e}"
    if isinstance(e, NET_ERRORS):
        return ("timeout" if "timed out" in str(e).lower() else "conn_error"), snip
    return "internal_error", snip


# ---------------------------------------------------------------- output

class SynapseExit(Exception):
    """可预期的退出(带人话消息)。

    旧实现到处 sys.exit(), 既打断调用栈也没法在测试里断言。
    现在统一抛这个, 由 main() 转成退出码 + 一条 stderr 消息。
    """
    def __init__(self, message="", code=1):
        super().__init__(message)
        self.message = message
        self.code = code


class Ctx:
    """所有输出的唯一出口。

    say()  给人看的(表格/提示)。--json 时自动改道 stderr, 保证 stdout 只有 JSON。
    json() 给机器看的, 永远走 stdout。
    die()  可预期错误: 抛 SynapseExit, 由 main 统一转退出码。
    """

    def __init__(self, out=None, err=None, as_json=False):
        self.out = out if out is not None else sys.stdout
        self.err = err if err is not None else sys.stderr
        self.as_json = as_json

    def say(self, *a, **kw):
        kw.setdefault("file", self.err if self.as_json else self.out)
        print(*a, **kw)

    def emit(self, text):
        print(text, file=self.out)

    def json(self, obj):
        self.emit(json.dumps(obj, ensure_ascii=False, indent=2))

    def die(self, msg, code=1):
        raise SynapseExit(msg, code)


# ---------------------------------------------------------------- commands


def _config_error_row(name, reason):
    """配置不完整的目标也占一行, 显式报错, 而不是默默跳过。"""
    return {"target": name, "model": "-", "test": "basic", "kind": "config_error",
            "http": 0, "latency_ms": 0, "usage": {}, "text": "",
            "snippet": re.sub(r"^\[!\]\s*", "", (reason or "配置不完整").strip())[:220]}


def targets_of(cfg, args):
    """展开要检查的 (name,url,key,models,entry)。
    会在内部对比上次快照自动维护 .dirty:
      - 目标被删/禁用 → 打脏标记(提醒清 pi 侧残留)
      - 出现过 #ERROR 哨兵值 → 视为情况变化打过标记
    注意: 若目标本身已消失(如被 import-from-pi 重建掉), 此处靠快照对比补提。
    """
    snapshot = os.path.join(HOME, ".targets_snapshot.json")
    cur = sorted(n for n, e in cfg["targets"].items() if e.get("enabled", True))
    prev = load_json(snapshot)
    if prev is None:
        save_json(snapshot, cur)
        prev = cur
    gone = [n for n in prev if n not in cur]
    if gone:
        mark_dirty(f"目标被移除/禁用: {', '.join(gone)}")
        save_json(snapshot, cur)
    elif cur != prev:
        save_json(snapshot, cur)
    out = []
    for name, entry in cfg["targets"].items():
        if getattr(args, "target", None) and name != args.target:
            continue
        if not entry.get("enabled", True):
            continue
        try:
            n, url, key, entry = resolve_target(cfg, name)
        except (SynapseExit, SystemExit) as e:
            # noqa: SystemExit 兼容老路径
            # 配置坏掉的站必须留在结果里: 旧实现塞个空 models, 该站一个测试都不跑,
            # 报告里也看不见 —— 用户会以为“全绿”, 实际是配置没填。
            out.append((name, "", "", None,
                        getattr(e, "message", None) or str(getattr(e, "code", "") or "配置不完整")))
            continue
        models = entry.get("models") or []
        if getattr(args, "model", None):
            models = [m for m in models if m == args.model]
        out.append((n, url, key, models, entry))
    return out


def build_plan(scope, extra=None):
    """按子命令返回要跑的测试项 key 列表(与 TEST_LABELS 顺序一致)。"""
    if scope == "diagnose":
        plan = ["basic", "stream", "tools", "tools_raw", "thinking"]
        for k in (extra or []):
            if k in TEST_LABELS and k not in plan:
                plan.append(k)
        return plan
    plan = ["basic"]
    for k in (extra or []):
        if k in TEST_LABELS and k not in plan:
            plan.append(k)
    return plan


def run_plan(url, key, model, plan, timeout=60, image_file=None):
    """按 plan 逐项探测, 返回 {test_key: result}。"""
    kw = {"timeout": timeout}
    mapping = {
        "basic": {},
        "stream": {"stream": True},
        "tools": {"tools": True},
        "tools_raw": {"tools": True},
        "thinking": {"thinking": True},
        "vision_user": {"image": True, "use_real_image": image_file},
        "vision_tool": {"image": True, "image_form": "tool", "use_real_image": image_file},
    }
    out = {}
    for k in plan:
        if k == "cache":
            out[k] = probe_cache(url, key, model, timeout=timeout)
            continue
        try:
            out[k] = probe(url, key, model, **mapping[k], **kw)
        except Exception as e:             # noqa: BLE001
            kind, snip = _net_or_internal(e)
            out[k] = {"kind": kind, "http": 0, "latency_ms": 0, "snippet": snip}
    return out


def probe_cache(url, key, model, timeout=60, samples=3):
    """三次同前缀请求, 看 cache_read_input_tokens 是否 > 0。
    取最优轮次判定(致少一轮读到了就算透传)，避免被单次 429/抖动带偏。
    判定:
      cache_passthrough — 至少一轮读到缓存(站方透传 prompt cache)
      cache_miss        — 全部为 0(站方不透传，pi 会反复全价重算)
    """
    prompts = [CACHE_PAD + CACHE_Q1, CACHE_PAD + CACHE_Q2, CACHE_PAD + CACHE_Q1][:max(3, samples)]
    try:
        rows = probe_multi(url, key, model, prompts, timeout=timeout)
    except Exception as e:                 # noqa: BLE001
        kind, snip = _net_or_internal(e)
        return {"kind": kind, "http": 0, "latency_ms": 0, "snippet": snip}
    first, second = rows[0], rows[-1]
    if first["kind"] not in ("ok", "ok_truncated", "ok_nonjson"):
        return {**first, "detail": "第一轮就失败，无法判缓存"}
    best = 0
    for r in rows:
        u = r.get("usage") or {}
        best = max(best, u.get("cache_read_input_tokens") or u.get("cache_read_tokens") or 0)
    u2 = second.get("usage") or {}
    read = best
    u1 = first.get("usage") or {}
    detail = (f"第1轮 in={u1.get('input_tokens')} cr={u1.get('cache_read_input_tokens', 0)} | "
              f"第2轮 in={u2.get('input_tokens')} cr={read} (共 {len(rows)} 轮)")
    kind = "cache_passthrough" if read else "cache_miss"
    if first["kind"] == "ok_truncated" or second["kind"] == "ok_truncated":
        pass  # 截断不影响缓存判定
    return {"kind": kind, "http": second.get("http", 200),
            "latency_ms": first["latency_ms"], "snippet": detail, "detail": detail,
            "usage": u2, "rounds": [{"usage": r.get("usage"), "ms": r["latency_ms"]} for r in rows]}


def _auto_issue_from_rows(rows, say=None):
    """把本轮体检里的“值得记一笔”的异常自动写入台账。
    只报真正需要行动的问题，避免噪声刷屏:
      - tool_call_broken   → agent 渠道损坏(最严重)
      - auth_failed/no_channel/auth_unavailable → 配置或账号真错了
      - 同一个 target 上 basic 仍能用但该模型挂 → 单模型故障
      - timeout/server_error 连续出现 → 稳定性
    模型把工具调用写成文本(tool_call_text)不自动开单: 它不影响 pi 使用。
    """
    say = say or print
    db = load_issues()
    changed = False
    by_target = {}
    for r in rows:
        by_target.setdefault(r["target"], []).append(r)
    for target, rs in by_target.items():
        alive = any(r["kind"] in ("ok", "ok_truncated", "ok_nonjson")
                    and r["test"] == "basic" for r in rs)
        # WAF 是站级现象(封 UA/出口 IP), 全站都拦时只开一条站级单, 不按模型刷
        basic = [r for r in rs if r["test"] == "basic"]
        if basic and all(r["kind"] == "waf_blocked" for r in basic):
            nid, created = issue_add_auto(
                db, target, "", "WAF/CDN拦截",
                f"全站 {len(basic)} 个模型均被拦截页挡回(HTTP {basic[0]['http']}) → 不是 key 问题。"
                f"拦回片段: {basic[0]['snippet'][:90]}",
                cause="站点 WAF/CDN 按 UA/出口 IP 拦截探测请求",
                plan="换出口或 UA 重试; pi 里同站若也被拦则该站暂时不可用")
            changed = changed or created
            say(f"  {'新建' if created else '再报'}问题 #{nid} (WAF 拦截)")
        for r in rs:
            k, tk = r["kind"], r["test"]
            if k == "config_error":
                nid, created = issue_add_auto(
                    db, target, "", "配置不完整",
                    f"该站本轮未做任何探针: {r['snippet'][:120]}",
                    cause="config.json 里缺 base_url 或 api_key(或 key_from_pi 指向的 provider 不存在)",
                    plan="补全 config.json 该目标字段, 或跑 synapse import-from-pi 重新生成")
                changed = changed or created
                say(f"  {'新建' if created else '再报'}问题 #{nid} (配置不完整)")
            elif k in ("auth_failed", "auth_unavailable"):
                nid, created = issue_add_auto(
                    db, target, r["model"], "配置/账号(key)",
                    f"[{tk}] {r['model']} → {k} (HTTP {r['http']}): {r['snippet'][:120]}",
                    cause="key 无效/欠费, 或上游账号掉了",
                    plan="核对 key、余额; 仍不通就找站方")
                changed = changed or created
                say(f"  {'新建' if created else '再报'}问题 #{nid}")
            elif k == "no_channel":
                nid, created = issue_add_auto(
                    db, target, r["model"], "模型名无渠道",
                    f"[{tk}] {r['model']} → 站方无此模型/分组 (HTTP {r['http']}): {r['snippet'][:110]}",
                    cause="模型 ID 与站内可用列表不匹配(常是站方下架或改名)",
                    plan="核对站内模型列表后改 config, 或从目标里摘掉该模型")
                changed = changed or created
                say(f"  {'新建' if created else '再报'}问题 #{nid}")
            elif k == "tool_call_broken":
                nid, created = issue_add_auto(
                    db, target, r["model"], "agent工具调用被破坏",
                    f"[{tk}] {r['model']} 的 tool_use 被渠道吐成坏JSON/文本 → 不能跑 agent: {r['snippet'][:100]}",
                    cause="渠道 tool-call 转译链损坏",
                    plan="把该模型排除出 pi 的 agent 场景，或改用支持 tool_use 的站")
                changed = changed or created
                say(f"  {'新建' if created else '再报'}问题 #{nid}")
            elif k in ("timeout", "server_error") and not alive:
                nid, created = issue_add_auto(
                    db, target, r["model"], "稳定性(挂死/5xx)",
                    f"[{tk}] {r['model']} {k} {r['latency_ms']}ms (该站本轮连基础都挂)",
                    cause="上游挂死/限流",
                    plan="由 watch 盯；连续多轮失败可临时禁用该站")
                changed = changed or created
                say(f"  {'新建' if created else '再报'}问题 #{nid}")
    if changed:
        save_issues(db)
    return changed


def _streak_hints(min_streak=2):
    """从 .outage.json 里挑出连续失败 N 轮的模型, 给"建议临时禁用"提示(不改配置)。"""
    snap = load_json(os.path.join(HOME, ".outage.json"), {}) or {}
    hints = []
    for key, st in sorted(snap.items()):
        if st.get("streak", 0) >= min_streak:
            t, m = key.split("||", 1)
            hints.append(f"[!] {t}/{m} 已连续 {st['streak']} 轮失败(最近 {st.get('last_kind')})"
                         f" → 可考虑临时禁用: 在 config.json 把 {t} 的 enabled 改 false")
    return hints


def _outage_track(rows):
    """累计每个 目标||模型 的成功/失败轮次和连续失败次数(.outage.json), 供 watch 长跑追踪时段性故障。"""
    GOOD = ("ok", "ok_truncated", "ok_nonjson", "ok_tool_use", "cache_passthrough")
    snap = load_json(os.path.join(HOME, ".outage.json"), {}) or {}
    for r in rows:
        if r["kind"] in ("config_error", "internal_error"):
            continue                      # 配置问题/我们自己的 bug 都不是网络故障, 不该污染连续失败计数
        st = snap.setdefault(f"{r['target']}||{r['model']}",
                             {"ok": 0, "fail": 0, "streak": 0, "last": "", "last_kind": ""})
        st["last"], st["last_kind"] = now(), r["kind"]
        if r["kind"] in GOOD:
            st["ok"] += 1
            st["streak"] = 0
        elif r["test"] == "basic":
            st["fail"] += 1
            st["streak"] += 1
    save_json(os.path.join(HOME, ".outage.json"), snap)
    return {
        "total": len(rows),
        "ok": sum(1 for r in rows if r["kind"] in GOOD),
        "bad": sum(1 for r in rows if r["kind"] in ("auth_failed", "no_channel",
                                                     "auth_unavailable", "config_error",
                                                     "internal_error")),
        "warn": sum(1 for r in rows if r["kind"] in ("tool_call_text", "cache_miss", "server_error",
                                                      "rate_limited", "upstream_400", "waf_blocked")),
        "dead": sum(1 for r in rows if r["kind"] in ("timeout", "conn_error", "tool_call_broken")),
    }


# 会自愈的异常种类: 站方限流/WAF/模型下架/临时 5xx 都可能在下一轮自行恢复。
RECOVER_KINDS = ("WAF/CDN拦截", "稳定性(挂死/5xx)", "配置/账号(key)", "模型名无渠道",
                 "配置不完整")


def _auto_recover_from_rows(rows, db=None, say=None):
    """体检重新变好的目标自动结单, 不只报不治。

    只动 auto=True 且种类属于“会自愈”的单, 且仅在**全量**体检里跑(单目标抽查
    不能证明整体好了)。第一次恢复只记一笔; 连续两轮都恢复则自动把 status
    改成 fixed —— 台账不会越堆越脏, 而手工单(看重人工判断)永不被碰。
    """
    GOOD = ("ok", "ok_truncated", "ok_nonjson", "ok_tool_use", "cache_passthrough")
    say = say or print
    db = db if db is not None else load_issues()
    ok_pairs = {(r["target"], r["model"]) for r in rows
                if r["test"] == "basic" and r["kind"] in GOOD}
    ok_targets = {t for t, _ in ok_pairs}
    changed = 0
    for i in db.get("issues", []):
        if i.get("status") != "open" or not i.get("auto"):
            continue
        if i.get("kind") not in RECOVER_KINDS:
            continue
        tgt, mdl = i.get("target"), i.get("model") or ""
        hit = ((tgt, mdl) in ok_pairs) if mdl else (tgt in ok_targets)
        if not hit:
            continue
        notes = i.setdefault("notes", [])
        prev = [n for n in notes if str(n.get("text", "")).startswith("[恢复]")]
        if len(prev) >= 1:                       # 连续第二轮恢复 → 结单
            i["status"] = "fixed"
            notes.append({"time": now(),
                          "text": "[恢复] 连续两轮体检均正常, 自动结单(auto)"})
            say(f"  ✅ 问题 #{i['id']} {tgt}/{mdl or '(整站)'} 连续两轮恢复 → 自动结单")
        else:
            notes.append({"time": now(),
                          "text": f"[恢复] 本轮体检正常({i.get('kind')}), 再观察一轮"})
            say(f"  ↺ 问题 #{i['id']} {tgt}/{mdl or '(整站)'} 已恢复, 待下一轮确认结单")
        changed += 1
    if changed:
        save_issues(db)
    return changed


def cmd_check(args, ctx):
    cfg = load_config()
    rows, t0 = [], time.time()
    stale = read_dirty()  # 目标清单自上次体检后被我方改过 → 提醒清理 pi 残留

    plan = build_plan("check", [k for k in ("vision_user", "tools", "cache")
                               if (getattr(args, "vision", False) and k == "vision_user")
                               or (getattr(args, "tools", False) and k == "tools")
                               or (getattr(args, "cache", False) and k == "cache")])

    def one(name, url, key, m, test_key):
        r = run_plan(url, key, m, [test_key], timeout=args.timeout,
                     image_file=getattr(args, "image_file", None))[test_key]
        r["test"] = test_key
        return {"target": name, "model": m, **r}

    jobs = []
    cfg_errors = []
    for n, u, k, ms, note in targets_of(cfg, args):
        if ms is None:                  # 配置不完整: 不跑探针, 但要占一行报错
            cfg_errors.append((n, note))
            continue
        for m in ms:
            for tk in plan:
                jobs.append((n, u, k, m, tk))
    if args.jobs > 1 and len(jobs) > 1:
        with futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = [ex.submit(one, *j) for j in jobs]
            rows = [f.result() for f in futs]
    else:
        rows = [one(*j) for j in jobs]

    # 配置坏掉的目标排在最前面 —— 这是最该先修的, 不该被埋在后面
    rows = [_config_error_row(n, note) for n, note in cfg_errors] + rows

    # 人类可读的输出统一走 ctx.say(): --json 时它会自动改道 stderr

    ctx.say(f"\n=== Synapse 连通性检查  {now()} ===")
    for r in rows:
        tag = {"vision_user": "🖼", "vision_tool": "🖼", "tools": "🔧", "tools_raw": "🔧", "cache": "💰"}.get(r.get("test"), "  ")
        ctx.say(f"{tag}[{r['target']:<10}] {r['model']:<28} {VERDICT.get(r['kind'], r['kind']):<38} "
            f"{r['latency_ms']}ms  {('HTTP ' + str(r['http'])) if r['http'] else ''}")
        if args.verbose and r["snippet"]:
            ctx.say(f"{'':12}└─ {r['snippet']}")
    ok_kinds = ("ok", "ok_truncated", "ok_nonjson", "ok_tool_use", "cache_passthrough")
    bad = [r for r in rows if r["kind"] not in ok_kinds]
    ctx.say(f"\n合计 {len(rows)} 项, 异常 {len(bad)} 项, 耗时 {time.time()-t0:.1f}s")

    # 提醒: 一周期内反复失败的目标 → 建议临时禁用(不自动改配置)
    for hint in _streak_hints():
        ctx.say(hint)

    # 提醒: 目标清单自上次体检后被我方改过 → 可能需要同步 pi 侧
    if stale:
        ts, what = (stale.split("\t", 1) + [""])[:2]
        ctx.say(f"\n[!] 目标清单有变更未复查  自 {ts}: {what}")
        if not args.target:            # 只在全量检查时确认清除, 单目标抽查不算
            clear_dirty()
            ctx.say("    已清除标记(本轮全量体检已覆盖当前清单)")

    # 自动开单: 连续错误/agent 渠道损坏/缓存出现透传都记一笔(带 24h 去重)
    if getattr(args, "auto_issue", False):
        _auto_issue_from_rows(rows, say=ctx.say)

    # 自愈: 全量体检里已恢复的自动单记一笔/结单(定向抽查不算, 不能证明整体好了)
    partial = bool(args.target or getattr(args, "model", None))
    if not partial:
        _auto_recover_from_rows(rows, say=ctx.say)

    # 落盘
    os.makedirs(REPORTS, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    stat = _outage_track(rows)
    if args.as_json:
        ctx.json({"time": now(), "summary": stat, "results": rows})
    payload = {"time": now(), "summary": stat, "results": rows, "dirty": stale,
               "partial": partial}
    save_json(os.path.join(REPORTS, f"check-{stamp}.json"), payload)
    # latest.json 只收全量快照: 带 --target/--model 的定向抽查不能把全景图盖成残缺的
    if not payload["partial"]:
        save_json(os.path.join(REPORTS, "latest.json"), payload)
    return 1 if bad else 0


def cmd_watch(args, ctx):
    ctx.say(f"[*] 周期监控已启动, 每 {args.interval}s 一次, Ctrl+C 退出")
    while True:
        try:
            cmd_check(argparse.Namespace(
                target=args.target, model=args.model, timeout=args.timeout,
                jobs=args.jobs, verbose=False,
                vision=getattr(args, "vision", False),
                tools=getattr(args, "tools", False),
                cache=getattr(args, "cache", False),
                image_file=getattr(args, "image_file", None),
                as_json=False), ctx)
        except (SynapseExit, SystemExit) as e:
            ctx.say(getattr(e, "message", None) or e)
        time.sleep(args.interval)


def cmd_diagnose(args, ctx):
    cfg = load_config()
    name, url, key, entry = resolve_target(cfg, args.target, args.api_key, args.base_url)
    model = args.model or (entry.get("models") or [None])[0]
    if not model:
        ctx.die("[!] 未指定模型")
    ctx.say(f"\n=== Synapse 诊断  {now()}  [{name}] {model} @ {url} ===\n")
    extra = []
    if getattr(args, "vision", False):
        extra += ["vision_user", "vision_tool"]
    if getattr(args, "cache", False):
        extra.append("cache")
    plan = build_plan("diagnose", extra)
    image_file = getattr(args, "image_file", None)
    results, by_test = {}, {}
    for k in plan:
        label = TEST_LABELS[k]
        r = run_plan(url, key, model, [k], timeout=args.timeout,
                     image_file=image_file)[k]
        results[label] = r
        by_test[k] = r
        ctx.say(f"{label:<30} {VERDICT.get(r['kind'], r['kind']):<40} {r['latency_ms']}ms")
        if r["snippet"]:
            ctx.say(f"{'':32}└─ {r['snippet'][:180]}")
    ctx.say("\n--- 结论与建议 ---")
    conclusions = []
    base = results[TEST_LABELS["basic"]]["kind"]
    if base in ("auth_failed",):
        conclusions.append("key 无效 → 检查 api key / 账户余额。")
    elif base == "waf_blocked":
        conclusions.append("被站方 WAF/CDN 拦截(返回的是拦截网页, 不是 API 错误) → 与 key 无关;"
                           " 多半是 UA/探测文案/出口 IP 被盯上了。可换 PROBE_TEXT 或换出口重试;"
                           " pi 里同站若也返回 HTML 拦截页, 则此站当前不可用。")
    elif base == "anti_probe":
        conclusions.append("被反测活拦截 → 站方封了探测文案, 用环境变量换一段正常对话文本重试。")
    elif base == "no_channel":
        conclusions.append("模型名不对或分组无渠道 → 核对站内模型ID(注意 [1M] 这类后缀只是标记,不发出去)。")
    elif base in ("ok", "ok_truncated", "ok_nonjson"):
        conclusions.append("基础链路 OK。")
    if results[TEST_LABELS["thinking"]]["kind"] == "thinking_unsupported":
        conclusions.append("该渠道不支持 thinking 参数 → 在 pi 的 models.json 中把该模型 reasoning 改为 false "
                           "(可运行: %s fix --target %s --model %s --fix disable-reasoning --apply)"
                           % (CMD, name, model))
    # 工具调用形态: 纯 tools 看能不能过, tools_raw 看返回结构完不完整
    tk = results[TEST_LABELS["tools"]]["kind"]
    rk = results[TEST_LABELS["tools_raw"]]["kind"]
    if tk == "thinking_unsupported":
        conclusions.append("注意: 带 tools 时命中 thinking 类 400, 同样需要关闭 reasoning。")
    elif tk in ("ok", "ok_truncated", "ok_tool_use", "tool_call_text"):
        if rk == "ok_tool_use":
            conclusions.append("工具调用 OK: 返回合规 tool_use 块, pi 的 agent 流程可用。")
        elif rk in ("tool_call_broken", "tool_call_text"):
            conclusions.append("❌ 工具调用被渠道破坏(吐成文本/坏JSON, 不是 tool_use 块) → 该站不能做 pi agent 任务, 只能纯聊天。"
                               "必要时在 models.json 里把该模型标成非工具模型，或换 runanytime/kool/windhub。")
        else:
            conclusions.append("工具调用链路通（未捕捉到坏文本）。")
    elif tk in ("timeout", "rate_limited", "server_error"):
        conclusions.append("⚠️ 带 tools 的请求超时/报错 → 该站工具链路不稳（cialo 实测就是这种“纯聊天可用、带工具就崩”）。")
    if TEST_LABELS["vision_user"] in results and results[TEST_LABELS["vision_user"]]["kind"] not in ("ok", "ok_truncated"):
        conclusions.append("该渠道不接受图像输入 → 在 pi 的 models.json 中把该模型 input 改为 [\"text\"] "
                           "(可运行: %s fix --target %s --model %s --fix disable-image --apply)"
                           % (CMD, name, model))
    if TEST_LABELS["vision_tool"] in results:
        vk = results[TEST_LABELS["vision_tool"]]["kind"]
        if vk in ("ok", "ok_truncated"):
            conclusions.append("toolResult注图 OK: pi 的 read 看图流程可用。")
        else:
            conclusions.append("toolResult注图不被该渠道接受(pi read 看图会失败) → 看图请直接粘贴图片进输入框, 或切换 runanytime/kool/windhub 等支持该形态的站。")
    if TEST_LABELS["cache"] in results:
        ck = results[TEST_LABELS["cache"]]["kind"]
        if ck == "cache_passthrough":
            conclusions.append("前缀缓存透传 → 长会话每轮只付增量, 省钱。")
        elif ck == "cache_miss":
            conclusions.append("前缀缓存不透传(全轮 cr=0) → pi 长会话每轮全价重算, 遇到长上下文成本翻倍。")
        else:
            conclusions.append("缓存测试未跑成(超时/报错), 无法判定。")
    for c in conclusions:
        ctx.say(" •", c)
    payload = {"time": now(), "target": name, "model": model, "base_url": url,
               "results": by_test, "conclusions": conclusions}
    if ctx.as_json:                        # stdout 只留 JSON, 表格已自动走 stderr
        ctx.json(payload)
    save_json(os.path.join(REPORTS, f"diagnose-{datetime.datetime.now():%Y%m%d-%H%M%S}.json"),
              payload)
    return 0


def _age_hours(ts, now_dt=None):
    """把 '2026-10-21 16:00:00' 算成"多少小时前"; 解析不了返回 None(手改坏的文件不该崩)。"""
    try:
        t = datetime.datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    return ((now_dt or datetime.datetime.now()) - t).total_seconds() / 3600.0


def _last_check(stale_hours=3.0):
    """最近一次**全量**体检的摘要(latest.json 只有全量体检才写)。

    stale=True 意味着数据已经比阈值更旧: 定时器/任务多半挂了。
    监控工具自己死掉却继续显示"上次全绿", 是最容易让人放心的假象。
    """
    d = load_json(os.path.join(REPORTS, "latest.json"), None)
    if not d:
        return None
    age = _age_hours(d.get("time"))
    return {"time": d.get("time"), "summary": d.get("summary") or {},
            "age_hours": None if age is None else round(age, 2),
            "stale": bool(age is not None and age > stale_hours)}


def cmd_status(args, ctx):
    """一览全局: 目标清单 / 脏标记 / 长跑失败统计 / 未解决台账。看板式单次输出。"""
    cfg = load_config()
    db = load_issues()
    snap = load_json(os.path.join(HOME, ".outage.json"), {}) or {}
    dirty = read_dirty()
    last = _last_check(getattr(args, "stale_hours", 3.0))
    if args.as_json:
        ctx.json({"time": now(), "targets": cfg["targets"], "outage": snap,
                  "dirty": dirty, "issues": db["issues"], "last_check": last})
        return 0

    ctx.say(f"\n=== Synapse 状态  {now()} ===")
    ctx.say(f"\n[目标清单] {sum(1 for e in cfg['targets'].values() if e.get('enabled', True))} 个启用")
    for n, e in cfg["targets"].items():
        on = "✔" if e.get("enabled", True) else "✗禁用"
        dflt = " (default)" if e.get("default") else ""
        ctx.say(f"  {on} {n:<15} models={len(e.get('models') or [])}{dflt}"
              f"{'  key_from_pi=' + e['key_from_pi'] if e.get('key_from_pi') else ''}")
    if dirty:
        ts, what = (dirty.split("\t", 1) + [""])[:2]
        ctx.say(f"\n[!] 脏标记(未复查): {what}  自 {ts}")

    # 监控器自己有没有在跑? latest.json 只在全量体检时写, 它的年龄就是"心跳"
    if last is None:
        ctx.say("\n[最近一次体检] 无记录 → 先跑一次全量 check"
                "(latest.json 只在全量体检时写, 定向抽查不算)")
    else:
        st = last["summary"]
        age = last["age_hours"]
        human = "时间无法解析" if age is None else f"{age:.1f}h 前"
        ctx.say(f"\n[最近一次体检] {last['time']}  ({human})   合计 {st.get('total', '?')} 项"
                f"  异常 {st.get('bad', 0)}  警告 {st.get('warn', 0)}  失败 {st.get('dead', 0)}")
        if last["stale"]:
            ctx.say(f"[!] 已经 {age:.1f}h 没有新的全量体检(阈值 {args.stale_hours}h)"
                    f" → 定时任务可能没在跑, 检查: {CMD} timer status")

    ctx.say("\n[长跑失败统计] (.outage.json, 由 check 累计)")
    if not snap:
        ctx.say("  (还没有数据, 先跑几次 check/watch)")
    else:
        rows = sorted(snap.items(), key=lambda kv: (-kv[1].get("streak", 0), -kv[1].get("fail", 0)))
        for key, st in rows:
            t, m = key.split("||", 1)
            flag = "🔴" if st.get("streak", 0) >= 2 else ("🟡" if st.get("fail") else "🟢")
            ctx.say(f"  {flag} {t:<12} {m:<28} ok={st.get('ok', 0):<4} fail={st.get('fail', 0):<4}"
                  f"连败={st.get('streak', 0):<3} 最近={st.get('last_kind', '')}")

    ctx.say(f"\n[问题台账] 未解决 {sum(1 for i in db['issues'] if i['status'] in ('open', 'doing'))} 条")
    for i in db["issues"]:
        if i["status"] in ("open", "doing"):
            ctx.say(f"  #{i['id']}[{i['status']}] {i['target'] or '-'}{('/' + i['model']) if i.get('model') else ''}:"
                  f" {i['symptom'][:60]}")
    return 0


def _schedule_status():
    """有没有任何机制在定期跑 check? 返回 (bool, 说明)。

    systemd 定时器被 disable 掉是最安静的一种失效: 不报错, 只是不再有新的
    体检。doctor 必须能说出"现在没人看"这句话。
    """
    rc, out = _systemctl("is-enabled", TIMER_UNIT)
    o = (out or "").strip().splitlines()
    o = o[0].strip() if o else ""
    if rc == 0 and o and "disabled" not in o:
        return True, f"systemd 用户定时器 {TIMER_UNIT} 已启用({o})"
    note = "本机没有 systemd --user" if rc == 127 else f"{TIMER_UNIT} 未启用({o or '状态未知'})"
    try:
        cr = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        txt = cr.stdout or ""
        if "synapse" in txt and "check" in txt:
            return True, "crontab 里有 synapse check"
        note += "; crontab 里也没有 synapse check"
    except (OSError, subprocess.SubprocessError):
        note += "; 读不到 crontab"
    return False, note


def _doctor_checks(stale_hours=3.0):
    """Synapse 自检: 每项都是只读本地检查, 不联网。返回 [{level,name,detail,hint}]。"""
    rows = []

    def add(level, name, detail, hint=""):
        rows.append({"level": level, "name": name, "detail": detail, "hint": hint})

    # 1. 数据目录: 必须在代码目录之外(否则升级/重装会连数据一起覆盖)
    home_abs, base_abs = os.path.abspath(HOME), os.path.abspath(BASE)
    if home_abs == base_abs or home_abs.startswith(base_abs + os.sep):
        add("fail", "数据目录", f"数据目录落在代码目录里: {home_abs}",
            f"用 SYNAPSE_HOME 指到 ~/.config/synapse(默认就是), 别放在源码树里")
    elif not os.path.isdir(home_abs):
        add("fail", "数据目录", f"不存在: {home_abs}", "跑任意子命令会自动创建")
    elif not os.access(home_abs, os.W_OK):
        add("fail", "数据目录", f"不可写: {home_abs}", "检查属主/权限")
    else:
        add("ok", "数据目录", home_abs)

    # 2. config.json: 存在性 + 目标数 + 默认站 + 权限(内含明文 key)
    cfg = load_json(CONFIG, None)
    tg = {}
    if cfg is None:
        add("fail", "config.json", f"不存在或不是合法 JSON: {CONFIG}",
            f"先运行: {CMD} import-from-pi (或 {CMD} sync-stations)")
    else:
        tg = cfg.get("targets") or {}
        enabled = [n for n, e in tg.items() if e.get("enabled", True)]
        if not tg:
            add("fail", "config.json", "没有任何 target", f"运行 {CMD} import-from-pi")
        else:
            dflt = [n for n, e in tg.items() if e.get("default")]
            add("ok", "config.json", f"{len(tg)} 个目标, {len(enabled)} 个启用"
                + (f", 默认 {dflt[0]}" if dflt else ""))
            if not dflt:
                add("warn", "默认目标", "没有任何目标标着 default",
                    "在 config.json 里给常用站加 \"default\": true")
        try:
            mode = stat.S_IMODE(os.stat(CONFIG).st_mode)
        except OSError as e:
            add("warn", "config.json 权限", f"读不到权限位: {e}")
        else:
            if mode & 0o077:
                add("warn", "config.json 权限",
                    f"{oct(mode)} 对同组/其他用户可读, 而里面有明文 api_key",
                    f"chmod 600 {CONFIG}")
            else:
                add("ok", "config.json 权限", oct(mode))

    # 3. key_from_pi 引用: 指向的 provider 必须真的存在, 否则该目标永远配置不完整
    provs = (load_json(PI_MODELS, None) or {}).get("providers") or {}
    dangling = [f"{n}→{e['key_from_pi']}" for n, e in tg.items()
                if e.get("key_from_pi") and e["key_from_pi"] not in provs]
    if dangling:
        add("warn", "key_from_pi 引用", "这些引用在 pi 配置里找不到: " + ", ".join(dangling),
            "补上 pi 里的 provider, 或在 config 里直接填 base_url/api_key")
    elif any(e.get("key_from_pi") for e in tg.values()):
        add("ok", "key_from_pi 引用", f"{len(provs)} 个 provider 全部可解析")
    elif tg:
        add("ok", "key_from_pi 引用", "未使用 key_from_pi 引用")

    # 4. 最近一次全量体检 + 时钟: 时间在未来说明本机时钟/时区不对, 统计会全错
    last = _last_check(stale_hours)
    if last is None:
        add("warn", "最近一次全量体检", "没有 reports/latest.json",
            f"跑一次全量体检: {CMD} check")
    else:
        age = last["age_hours"]
        if age is not None and age < -0.1:
            add("warn", "时钟", f"latest.json 的时间在未来({last['time']}), 本机时钟/时区可能不对",
                "校时: sudo timedatectl set-ntp true")
        elif age is None:
            add("warn", "最近一次全量体检", f"时间无法解析: {last['time']!r}")
        elif last["stale"]:
            add("warn", "最近一次全量体检",
                f"{last['time']} ({age:.1f}h 前), 已超过 {stale_hours}h 阈值",
                f"检查: {CMD} timer status")
        else:
            add("ok", "最近一次全量体检", f"{last['time']} ({age:.1f}h 前)")

    # 5. 是否有东西在定期跑
    scheduled, how = _schedule_status()
    add("ok" if scheduled else "warn", "定期体检", how,
        "" if scheduled else f"启用: {CMD} timer on --interval 1h --now")

    # 6. 台账: 能解析, 且长期 open 的单要有人处理
    try:
        db = load_issues()
    except SynapseExit as e:
        add("fail", "问题台账", f"读不出来: {e.message}")
    else:
        open_is = [i for i in db["issues"] if i.get("status") in ("open", "doing")]
        if not open_is:
            add("ok", "问题台账", f"共 {len(db['issues'])} 条, 无未解决")
        else:
            ages = []
            for i in open_is:
                a = _age_hours(i.get("time"))
                if a is not None:
                    ages.append(a / 24.0)
            if ages and max(ages) > 14:
                add("warn", "问题台账",
                    f"未解决 {len(open_is)} 条, 最老一条已 open {max(ages):.0f} 天",
                    f"review: {CMD} issue list --status open")
            else:
                add("ok", "问题台账", f"未解决 {len(open_is)} 条, 都在 14 天内")

    # 7. 报告目录: 只报事实, 超过阈值才提醒(磁盘是会被撑满的)
    try:
        names = [n for n in os.listdir(REPORTS) if n.endswith(".json")]
        total = sum(os.path.getsize(os.path.join(REPORTS, n)) for n in names)
    except OSError:
        add("ok", "报告目录", "还没有报告")
    else:
        msg = f"{len(names)} 个报告, {total / 1048576:.1f} MB"
        if len(names) > 500 or total > 50 * 1048576:
            add("warn", "报告目录", msg, f"可以清理旧报告: rm -f {REPORTS}/check-*.json")
        else:
            add("ok", "报告目录", msg)

    # 8. 脏标记: 目标清单改过但没做全量复查
    dirty = read_dirty()
    if dirty:
        ts, what = (dirty.split("\t", 1) + [""])[:2]
        add("warn", "脏标记", f"{what} (自 {ts}) 尚未全量复查",
            f"跑一次全量: {CMD} check (定向抽查不算)")
    else:
        add("ok", "脏标记", "无")

    # 9. 运行环境
    v = sys.version_info
    if (v.major, v.minor) >= (3, 8):
        add("ok", "Python", f"{v.major}.{v.minor}.{v.micro}")
    else:
        add("fail", "Python", f"{v.major}.{v.minor}.{v.micro} 太旧", "需要 3.8+")
    return rows


def cmd_doctor(args, ctx):
    """自检: 诊断 Synapse 自己(只读, 不联网)。"""
    rows = _doctor_checks(getattr(args, "stale_hours", 3.0))
    icon = {"ok": "✔", "warn": "⚠", "fail": "✘"}
    summary = {lv: sum(1 for r in rows if r["level"] == lv) for lv in ("ok", "warn", "fail")}
    if ctx.as_json:
        ctx.json({"time": now(), "checks": rows, "summary": summary})
    else:
        ctx.say(f"\n=== Synapse 自检  {now()} ===")
        for r in rows:
            ctx.say(f"  {icon[r['level']]} {r['name']}: {r['detail']}")
            if r["hint"] and r["level"] != "ok":
                ctx.say(f"      → {r['hint']}")
        ctx.say(f"\n通过 {summary['ok']} 项, 警告 {summary['warn']} 项, 故障 {summary['fail']} 项")
        if not summary["fail"] and not summary["warn"]:
            ctx.say("全部通过。")
        elif not summary["fail"]:
            ctx.say("没有故障, 上面几条警告值得处理一下。")
        else:
            ctx.say("有故障项, 先按 → 后面的提示修。")
    return 1 if summary["fail"] else 0


def _synced_log_line():
    rep = load_json(os.path.join(REPORTS, "latest.json"), {}) or {}
    s = rep.get("summary") or {}
    if not s:
        return None
    return (f"- **{rep.get('time', '')}** — 共 {s.get('total', 0)} 项: "
            f"✅{s.get('ok', 0)} / ⚠{s.get('warn', 0)} / ❌{s.get('bad', 0) + s.get('dead', 0)}"
            f"（详见 reports/latest.json，或 `{CMD} status`）")


def cmd_sync_stations(args, ctx):
    """从 STATIONS.md 读取站清单 → 同步到 config.json → 可选立刻体检。"""
    if not os.path.exists(STATIONS):
        ctx.die(f"[!] 缺少 {STATIONS}")
    new = stations_to_config(say=ctx.say)
    old = load_json(CONFIG, {}) or {}
    oldt = old.get("targets", {})

    # 忠实转录: 用户在 markdown 里写什么就是什么。继承 default 标记。
    for name, e in new["targets"].items():
        if oldt.get(name, {}).get("default"):
            e["default"] = True
    if args.default:
        for e in new["targets"].values():
            e.pop("default", None)
        if args.default in new["targets"]:
            new["targets"][args.default]["default"] = True
        else:
            ctx.die(f"[!] --default {args.default} 不在站清单里")
    if not any(e.get("default") for e in new["targets"].values()):
        first = next(iter(new["targets"]), None)
        if first:
            new["targets"][first]["default"] = True

    added = [n for n in new["targets"] if n not in oldt]
    removed = [n for n in oldt if n not in new["targets"]]
    changed = [n for n in new["targets"] if n in oldt and oldt[n] != new["targets"][n]]

    save_json(CONFIG, new)
    chmod_private(CONFIG)
    ctx.say(f"[同步] {STATIONS} → {CONFIG}")
    ctx.say(f"  站数: {len(oldt)} → {len(new['targets'])}"
          + (f"  新增: {', '.join(added)}" if added else "")
          + (f"  移除: {', '.join(removed)}" if removed else "")
          + (f"  变更: {', '.join(changed)}" if changed else ""))
    for n in added + changed + removed:
        mark_dirty(f"sync-stations 导致目标清单变更: {n}")

    # 把本轮体检结果回写 STATIONS.md 日志区(只动 SYNC:LOG 之间)
    if args.log:
        line = _synced_log_line()
        if line:
            _append_log(line)
            ctx.say("  已把最近一次体检摘要写入 STATIONS.md 日志区")

    if args.check:
        ctx.say()
        ns = argparse.Namespace(target=None, model=None, timeout=args.timeout, jobs=args.jobs,
                                verbose=args.verbose, vision=args.vision, tools=args.tools,
                                cache=args.cache, image_file=args.image_file,
                                auto_issue=True, as_json=False)
        return cmd_check(ns, ctx)
    return 0


def _append_log(line):
    if not os.path.exists(STATIONS):
        return
    with open(STATIONS, encoding="utf-8") as f:
        src = f.read()
    begin, end = "<!-- SYNC:LOG:BEGIN -->", "<!-- SYNC:LOG:END -->"
    if begin not in src or end not in src:
        return
    head, rest = src.split(begin, 1)
    mid, tail = rest.split(end, 1)
    if not line.startswith("-"):
        return
    mid = mid.rstrip() + "\n" + line + "\n"
    open(STATIONS, "w", encoding="utf-8").write(head + begin + mid + end + tail)


def cmd_fix(args, ctx):
    """默认 dry-run 只预览; --apply 才写盘(用户下令)。"""
    pi = load_pi_models()
    prov = pi["providers"].get(args.target)
    if not prov:
        ctx.die(f"[!] pi 配置里没有 provider: {args.target}")
    target = None
    for m in prov.get("models", []):
        if m.get("id") == args.model:
            target = m
            break
    if not target:
        ctx.die(f"[!] provider {args.target} 下没有模型 {args.model}")

    if args.fix == "disable-reasoning":
        backup = PI_MODELS + f".bak.{datetime.datetime.now():%Y%m%d-%H%M%S}"
        patch = {"reasoning": False}
        if "thinkingLevelMap" in target:
            patch["-thinkingLevelMap"] = target["thinkingLevelMap"]
        ctx.say("[预览] 将对", f"{args.target}/{args.model}")
        ctx.say(f"  reasoning: {target.get('reasoning')} -> False")
        if "thinkingLevelMap" in target:
            ctx.say("  删除 thinkingLevelMap")
        ctx.say(f"  备份路径: {backup}")
        if not args.apply:
            ctx.say("\n(仅预览。确认要改请加 --apply)")
            return
        pi_bak = json.loads(json.dumps(pi))  # 快照
        target["reasoning"] = False
        target.pop("thinkingLevelMap", None)
        import shutil
        shutil.copy2(PI_MODELS, backup)
        save_json(PI_MODELS, pi)
        ctx.say(f"[完成] 已写入 {PI_MODELS} (备份: {backup})。重启 pi 生效。")
    elif args.fix == "disable-image":
        cur = target.get("input", [])
        if cur == ["text"]:
            ctx.say(f"[i] {args.target}/{args.model} 的 input 已经是 [\"text\"], 无需修改")
            return
        backup = PI_MODELS + f".bak.{datetime.datetime.now():%Y%m%d-%H%M%S}"
        ctx.say("[预览] 将对", f"{args.target}/{args.model}")
        ctx.say(f"  input: {cur} -> [\"text\"]")
        ctx.say(f"  备份路径: {backup}")
        if not args.apply:
            ctx.say("\n(仅预览。确认要改请加 --apply)")
            return
        import shutil
        shutil.copy2(PI_MODELS, backup)
        target["input"] = ["text"]
        save_json(PI_MODELS, pi)
        ctx.say(f"[完成] 已写入 {PI_MODELS} (备份: {backup})。重启 pi 生效。")
    else:
        ctx.die(f"[!] 未知修复类型: {args.fix}")


def cmd_import(args, ctx):
    pi = load_pi_models()
    cfg = {"$comment": "Synapse 目标配置。key_from_pi=引用pi里的provider(不重复存key); 也可直接填 base_url/api_key。",
           "targets": {}}
    for name, prov in pi.get("providers", {}).items():
        cfg["targets"][name] = {
            "key_from_pi": name,
            "enable": None,
            "enabled": True,
            "models": [m["id"] for m in prov.get("models", [])],
        }
    cfg["targets"][args.default] = cfg["targets"].get(args.default, {"enabled": True})
    cfg["targets"][args.default]["default"] = True
    save_json(CONFIG, cfg)
    mark_dirty("import-from-pi 重建目标清单")
    ctx.say(f"[完成] 已从 pi 导入 {len(pi.get('providers', {}))} 个目标 -> {CONFIG}")
    if args.edit_hint:
        ctx.say("可编辑该文件增删目标、留 key_from_pi 引用, 或填独立 base_url/api_key add_new。")


def cmd_cron(args, ctx):
    exe = shutil.which("synapse") or os.path.abspath(__file__)
    if exe.endswith("synapse") and os.access(exe, os.X_OK):
        line = f"{args.schedule} {exe} check >/dev/null 2>&1"
    else:
        line = (f"{args.schedule} /usr/bin/python3 {exe} check >/dev/null 2>&1")
    if args.install:
        cur = os.popen("crontab -l 2>/dev/null").read()
        if "synapse.py check" in cur or "synapse check" in cur:
            ctx.say("[i] crontab 已存在, 跳过")
            return
        new = (cur.rstrip("\n") + "\n" + line + "\n# synapse\n") if cur.strip() else f"{line}\n# synapse\n"
        p = os.popen("crontab -", "w")
        p.write(new)
        p.close()
        ctx.say("[完成] 已写入 crontab:")
    ctx.say(" ", line)


def _systemctl(*a):
    """跑 systemctl --user, 返回 (rc, 合并输出)。"""
    try:
        r = subprocess.run(
            ["systemctl", "--user", *a], capture_output=True, text=True, timeout=30)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, "systemctl 不存在"
    except (OSError, subprocess.SubprocessError) as e:
        # 只兜系统层问题; 我们自己的 bug(如类型错)要炸出来, 别伪装成"没装 systemd"
        return 1, f"{e}"


TIMER_UNIT = "synapse-check.timer"
SERVICE_UNIT = "synapse-check.service"
USER_UNIT_DIR = os.path.expanduser("~/.config/systemd/user")

# 内嵌单元模板: 源件在 packaging-src/systemd/, 这里留一份副本,
# 这样从源码目录直接跑(未装 deb)时也能用 timer。
UNIT_SERVICE = """[Unit]
Description=Synapse 中转站连通性体检
Documentation=man:synapse(1)

[Service]
Type=oneshot
ExecStart={exe} check --auto-issue
SuccessExitStatus=0 1
TimeoutStartSec=1800
Nice=10
IOSchedulingClass=idle
"""

UNIT_TIMER = """[Unit]
Description=Synapse 定时体检
Documentation=man:synapse(1)

[Timer]
OnStartupSec=1min
OnUnitActiveSec=1h
AccuracySec=1min
RandomizedDelaySec=30s
Persistent=false
Unit=synapse-check.service

[Install]
WantedBy=timers.target
"""


def _unit_present(name):
    for d in ("/usr/lib/systemd/user", "/lib/systemd/user",
              "/etc/systemd/user", USER_UNIT_DIR):
        if os.path.exists(os.path.join(d, name)):
            return True
    return False


def _ensure_units():
    """确保 systemd 能找到两个单元; 缺则写一份到用户目录。"""
    os.makedirs(USER_UNIT_DIR, exist_ok=True)
    exe = shutil.which("synapse") or os.path.abspath(__file__)
    if not os.access(exe, os.X_OK):
        exe = f"/usr/bin/python3 {exe}"
    wrote = []
    for name, tpl in ((SERVICE_UNIT, UNIT_SERVICE), (TIMER_UNIT, UNIT_TIMER)):
        if _unit_present(name):
            continue
        path = os.path.join(USER_UNIT_DIR, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(tpl.format(exe=exe))
        wrote.append(path)
    return wrote


def cmd_timer(args, ctx):
    """systemd 用户定时器管理。
    若系统未装 systemd 用户会话(容器/裸 shell), 退回 crontab。"""
    action = args.action
    if action == "on":
        if _systemctl("show-environment")[0] != 0:
            ctx.die("[!] 当前无 systemd 用户会话(容器环境?)，请改用: synapse cron --install")
        wrote = _ensure_units()
        for p in wrote:
            ctx.say(f"[i] 已写入单元: {p}")
        # 间隔通过 drop-in 覆盖，不动包/用户目录里的 unit 本身
        os.makedirs(os.path.join(USER_UNIT_DIR, f"{TIMER_UNIT}.d"), exist_ok=True)
        with open(os.path.join(USER_UNIT_DIR, f"{TIMER_UNIT}.d", "override.conf"),
                  "w", encoding="utf-8") as f:
            f.write(f"[Timer]\nOnUnitActiveSec=\nOnUnitActiveSec={args.interval}\n"
                    f"OnActiveSec={args.interval}\n")
        _systemctl("daemon-reload")
        rc, out = _systemctl("enable", "--now", TIMER_UNIT)
        if rc != 0:
            ctx.die(f"[!] 启用失败: {out.strip()}")
        ctx.say(f"[完成] 已启用 {TIMER_UNIT} (每 {args.interval} 一次)")
        if args.now:
            rc2, out2 = _systemctl("start", "--no-block", SERVICE_UNIT)
            ctx.say("[i] 已触发首轮体检(后台跑)" if rc2 == 0 else f"[!] 首轮触发失败: {out2.strip()}")
        rc3, out3 = _systemctl("is-enabled", TIMER_UNIT)
        ctx.say(f"    状态: {out3.strip() or '(未知)'}")
    elif action == "off":
        rc, out = _systemctl("disable", "--now", TIMER_UNIT)
        ctx.say("[完成] 已停用" if rc == 0 else f"[i] {out.strip()}")
    elif action == "run":
        rc, out = _systemctl("start", "--no-block", SERVICE_UNIT)
        ctx.say("[完成] 已触发一轮 check(后台跑, 用 synapse timer log 看输出)" if rc == 0
              else f"[!] {out.strip()}")
    elif action == "log":
        try:
            r = subprocess.run(
                ["journalctl", "--user", "-u", SERVICE_UNIT, "-n", "50", "--no-pager"],
                capture_output=True, text=True, timeout=30)
            ctx.say(r.stdout or r.stderr)
        except (OSError, subprocess.SubprocessError) as e:
            ctx.say(f"[!] 读日志失败: {e}")
    else:  # status
        rc, out = _systemctl("is-enabled", TIMER_UNIT)
        ctx.say(f"{TIMER_UNIT}: {out.strip() or '未安装'}")
        rc2, out2 = _systemctl("list-timers", TIMER_UNIT, "--no-pager")
        ctx.say(out2.rstrip() or "(无定时器记录)")
        ctx.say("\n命令: synapse timer on --interval 1h | off | run | log")


# ---------------------------------------------------------------- main


# ---------------------------------------------------------------- issues

ISSUES = os.path.join(HOME, "issues.json")

def load_issues():
    d = load_json(ISSUES, {"issues": []})
    d.setdefault("issues", [])
    return d

def save_issues(d):
    save_json(ISSUES, d)

def _print_issues(ctx, db, flt="all"):
    for i in db["issues"]:
        if flt != "all" and i["status"] != flt:
            continue
        tag = "自动" if i.get("auto") else "手工"
        ctx.say(f"[#{i['id']}][{i['status']:<7}] {i['time']}  "
              f"{i['target'] or '-'}{('/' + i['model']) if i.get('model') else ''}  ({tag}/{i.get('kind') or '-'})")
        ctx.say(f"    现象: {i['symptom']}")
        if i.get("cause"):
            ctx.say(f"    原因: {i['cause']}")
        if i.get("plan"):
            ctx.say(f"    计划: {i['plan']}")
        for n_, no in enumerate(i.get("notes", []), 1):
            t_ = no.get("text") if isinstance(no, dict) else str(no)
            ctx.say(f"    备注{n_}: {t_}")
    n_open = sum(1 for i in db["issues"] if i["status"] == "open")
    ctx.say(f"\n共 {len(db['issues'])} 条, 未解决 {n_open} 条")


def _find_issue(db, iid):
    for i in db["issues"]:
        if i["id"] == iid:
            return i
    raise SynapseExit(f"[!] 没有 #{iid}")


def cmd_issue(args, ctx):
    db = load_issues()
    args.id = getattr(args, "id", None) or getattr(args, "id_pos", None)
    if args.action == "add":
        n = max([i["id"] for i in db["issues"]], default=0) + 1
        db["issues"].append({
            "id": n, "time": now(), "status": "open",
            "target": args.target or "", "model": args.model or "",
            "kind": getattr(args, "kind", None) or "",
            "symptom": args.symptom, "cause": args.cause or "",
            "plan": args.plan or "", "notes": []
        })
        save_issues(db)
        ctx.say(f"[#{n}] 已记录: {args.symptom}")
    elif args.action == "list":
        flt = args.status or "all"
        rows = [i for i in db["issues"] if flt == "all" or i["status"] == flt]
        if ctx.as_json:
            ctx.json({"total": len(rows),
                      "open": sum(1 for i in rows if i["status"] == "open"),
                      "filter": flt, "issues": rows})
        else:
            _print_issues(ctx, db, flt)
    elif args.action == "note":
        it = _find_issue(db, args.id)
        it.setdefault("notes", []).append({"time": now(), "text": args.symptom})
        save_issues(db)
        ctx.say(f"[#{it['id']}] 已加备注")
    elif args.action == "status":
        st = args.new_status or getattr(args, "status_pos", None)
        it = _find_issue(db, args.id)
        it["status"] = st
        it.setdefault("notes", []).append({"time": now(), "text": f"状态 → {st}" + ("  " + args.text if args.text else "")})
        save_issues(db)
        ctx.say(f"[#{it['id']}] 状态 → {st}")
    elif args.action == "rm":
        it = _find_issue(db, args.id)
        db["issues"] = [i for i in db["issues"] if i["id"] != args.id]
        save_issues(db)
        ctx.say(f"[#{args.id}] 已删除(原现象: {it.get('symptom', '')[:40]})")
    return 0


def issue_add_auto(db, target, model, kind, symptom, cause="", plan="", ts=None, dedup_hours=24):
    """自动开单: 相同 target+model+kind 在 dedup_hours 内有未关单则不重复建，只追加备注。
    ts: 用于判断重复的时间字符串(默认现在)。
    """
    key = (target, model, kind)
    now_dt = datetime.datetime.now()
    for i in db["issues"]:
        if (i.get("target"), i.get("model"), i.get("kind")) != key:
            continue
        if i.get("status") in ("fixed", "wontfix"):
            continue
        try:
            t = datetime.datetime.strptime(i["time"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError) as _e:   # 手改坏的 issues.json 不该崩
            t = now_dt
        if (now_dt - t).total_seconds() > dedup_hours * 3600:
            continue
        i.setdefault("notes", []).append({"time": now(), "text": f"再次复现({ts or now()}): {symptom[:120]}"})
        return i["id"], False
    n = max([i["id"] for i in db["issues"]], default=0) + 1
    db["issues"].append({"id": n, "time": now(), "status": "open",
                         "target": target, "model": model, "kind": kind,
                         "symptom": symptom, "cause": cause, "plan": plan,
                         "notes": [], "auto": True})
    return n, True

def main(argv=None, out=None, err=None):
    """返回退出码（不再 sys.exit），输出流可注入 → CLI 可端到端测试。"""
    ap = argparse.ArgumentParser(description="Synapse — pi 模型连通性监控/诊断")
    ap.add_argument("--version", action="version",
                    version=f"synapse {__version__}",
                    help="显示版本号")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check", help="一次性连通性检查")
    p.add_argument("--target"); p.add_argument("--model")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--vision", action="store_true", help="每模型额外测一次图像输入(✉探测数翻倍)")
    p.add_argument("--tools", action="store_true", help="每模型额外测工具调用+结构完整性(🔧，抓agent坏渠道)")
    p.add_argument("--cache", action="store_true", help="每模型额外测前缀缓存是否透传(💰，验 issue#3)")
    p.add_argument("--image-file", help="用真实图片文件代替内置色块(测图像输入时)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="额外输出 JSON 摘要(便于接脚本/仪表盘)")
    p.add_argument("--auto-issue", action="store_true",
                   help="异常自动写入问题台账(同日同因去重), 坏得多的站自己开单")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("watch", help="周期监控(前台常驻)")
    p.add_argument("--interval", type=int, default=300)
    p.add_argument("--target"); p.add_argument("--model")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--vision", action="store_true", help="每轮都带上图像输入测试(✉)")
    p.add_argument("--tools", action="store_true", help="每轮都带上工具调用测试(🔧)")
    p.add_argument("--cache", action="store_true", help="每轮都带上缓存透传测试(💰)")
    p.add_argument("--image-file", help="watch 时图像测试用的真实图片")
    p.set_defaults(fn=cmd_watch)

    p = sub.add_parser("diagnose", help="单模型深度诊断(基础/流式/工具/thinking)")
    p.add_argument("--target", required=True)
    p.add_argument("--model"); p.add_argument("--api-key"); p.add_argument("--base-url")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--vision", action="store_true", help="附带图像输入测试")
    p.add_argument("--cache", action="store_true", help="附带前缀缓存测试(💰)")
    p.add_argument("--image-file", help="用真实图片文件代替内置色块(更适合验证“看得懂图”)")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="stdout 输出机器可读 JSON(人话走 stderr)")
    p.set_defaults(fn=cmd_diagnose)

    p = sub.add_parser("fix", help="修复pi配置(默认预览, --apply 才写入)")
    p.add_argument("--target", required=True, help="provider名")
    p.add_argument("--model", required=True, help="模型id")
    p.add_argument("--fix", default="disable-reasoning", choices=["disable-reasoning", "disable-image"])
    p.add_argument("--apply", action="store_true", help="真的写入(用户下令才用)")
    p.set_defaults(fn=cmd_fix)

    p = sub.add_parser("import-from-pi", help="从 ~/.pi/agent/models.json 导入目标")
    p.add_argument("--default", default=None, help="设为默认目标的provider名")
    p.add_argument("--edit-hint", action="store_true")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("cron", help="用 crontab 做定期检查")
    p.add_argument("--schedule", default="0 * * * *")
    p.add_argument("--install", action="store_true")
    p.set_defaults(fn=cmd_cron)

    p = sub.add_parser("timer", help="systemd 用户定时器(比 crontab 更符合 Debian 惯例)")
    p.add_argument("action", nargs="?", default="status",
                   choices=["on", "off", "status", "log", "run"],
                   help="on=启用 off=停用 status=状态 log=最近日志 run=立即跑一次")
    p.add_argument("--interval", default="1h", help="check 间隔(systemd 写法, 如 30min/1h/6h)")
    p.add_argument("--now", action="store_true", help="启用后立即跑一轮")
    p.set_defaults(fn=cmd_timer)

    p = sub.add_parser("issue", help="问题台账: add/list/note/status/rm")
    p.add_argument("action", choices=["add", "list", "note", "status", "rm"])
    p.add_argument("--target"); p.add_argument("--model")
    p.add_argument("--kind", help="add: 问题种类(如 agent工具/看图/thinking/缓存)")
    p.add_argument("--symptom", help="add: 现象描述")
    p.add_argument("--cause", help="add: 已定位的原因")
    p.add_argument("--plan", help="add: 优化计划")
    p.add_argument("id_pos", nargs="?", type=int, help="note/status/rm: 问题编号(位置参数)")
    p.add_argument("--id", type=int, help="note/status/rm: 问题编号(也可用位置参数)")
    p.add_argument("--text", help="note: 备注内容 / status: 可选说明")
    p.add_argument("--new-status", choices=["open", "doing", "done", "wontfix"],
                   help="status: 新状态(推荐写法)")
    p.add_argument("--status", "--filter", dest="status", default="all",
                   choices=["all", "open", "doing", "done", "wontfix"],
                   help="list: 只列某个状态(默认 all)")
    p.add_argument("status_pos", nargs="?", choices=["open", "doing", "done", "wontfix"],
                   help="status: 新状态(位置参数, 与 --new-status 等价)")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="list: 输出 JSON 而不是表格")
    p.set_defaults(fn=cmd_issue)

    p = sub.add_parser("sync-stations",
                       help="从 STATIONS.md 同步站清单到 config.json(你的 markdown 是数据源)")
    p.add_argument("--default", help="指定默认站(名字)")
    p.add_argument("--check", action="store_true", help="同步后立刻体检")
    p.add_argument("--tools", action="store_true")
    p.add_argument("--cache", action="store_true")
    p.add_argument("--vision", action="store_true")
    p.add_argument("--image-file")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--log", action="store_true",
                   help="把最近一次体检摘要回写到 STATIONS.md 日志区")
    p.set_defaults(fn=cmd_sync_stations)

    p = sub.add_parser("doctor", help="自检: 数据目录/权限/定时器/新鲜度/台账(只读, 不联网)")
    p.add_argument("--json", dest="as_json", action="store_true")
    p.add_argument("--stale-hours", type=float, default=3.0,
                   help="超过这么多小时没有全量体检就算陈旧(默认 3)")
    p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("status", help="一览: 目标清单 + 台账 + 长跑失败统计 + 上次体检新鲜度")
    p.add_argument("--json", dest="as_json", action="store_true")
    p.add_argument("--stale-hours", type=float, default=3.0,
                   help="超过这么多小时没有全量体检就告警(默认 3)")
    p.set_defaults(fn=cmd_status)

    ctx = Ctx(out, err)
    try:
        args = ap.parse_args(argv)        # --version/--help 在这里抛 SystemExit
        ctx.as_json = bool(getattr(args, "as_json", False))
        return args.fn(args, ctx) or 0
    except SynapseExit as e:
        if e.message:
            print(e.message, file=ctx.err)
        return e.code
    except SystemExit as e:                 # argparse --version / --help
        return int(e.code or 0)
    except KeyboardInterrupt:
        print("\n[中断]", file=ctx.err)
        return 130


if __name__ == "__main__":
    sys.exit(main())
