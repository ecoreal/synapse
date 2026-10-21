#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synapse 探测层: 真正发请求的地方。**只读** —— 不写任何配置。

一个探针炸了不能把整轮体检带走(那是"单条失败"和"整站全挂"的区别),
但也不能把所有异常都说成"站连不上"(我们自己的 bug 会被伪装成站方故障,
用户就去追一个健康的站)。所以这里所有兜底都过 _net_or_internal() 分诊。
"""
import base64
import http.client
import json
import os
import ssl
import struct
import time
import urllib.error
import urllib.request
import zlib

from synapse_classify import (_judge_tool_resp, _looks_html, classify)

import re

# --- 脱敏 -------------------------------------------------------------------
# 报告会被贴到群里/issue 里求助, 而站方完全可能在错误体里回显请求头(见过)。
# 于是 key 跟着 snippet 落进报告文件、终端 scrollback、HTML 仪表盘。
# 这类泄露事后发现不了, 所以必须写盘前就抹掉, 不能指望站方客气。
_RE_SK = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")
_RE_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
_RE_FIELD = re.compile(
    r'(?i)("(?:api[_-]?key|authorization|x-api-key|access[_-]?token|'
    r'secret|token)"\s*:\s*)"[^"]{4,}"')
_RE_HEADER = re.compile(r"(?i)\b(x-api-key|api[_-]?key)\s*[:=]\s*\S{4,}")


def redact(text, secrets=()):
    """抹掉像密钥的东西, 但保留足以定位问题的信息。

    刻意不整段替换: 排查时要看到 "401 invalid key" 这种字眼,
    全吃掉等于把证据也毁了。
    """
    if not text:
        return text
    out = str(text)
    for sec in secrets:                    # 已知的真实 key: 精确替换
        if sec and len(sec) >= 6:
            out = out.replace(sec, "***")
    out = _RE_SK.sub("sk-***", out)
    out = _RE_BEARER.sub(lambda m: f"{m.group(1)} ***", out)
    out = _RE_FIELD.sub(lambda m: f'{m.group(1)}"***"', out)
    out = _RE_HEADER.sub(lambda m: f"{m.group(1)}: ***", out)
    return out


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


# ---------------------------------------------------------------- probe


# 注意: run_plan / probe_cache 通过**本模块的全局名**调用 probe。
# 想打桩时 patch synapse_probe.probe; patch synapse.probe 会静默失效
# (synapse.py 里的 probe 只是给外部读的别名, 不是查找起点)。
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
            "snippet": redact(snippet.replace("\n", " "), (key,))}


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
        out.append({"kind": kind, "http": http,
                    "snippet": redact(snippet.replace("\n", " "), (key,)),
                    "usage": usage, "text": redact(text_out, (key,)),
                    "latency_ms": int((time.time() - t0) * 1000)})
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
