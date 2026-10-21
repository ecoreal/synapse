#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synapse 判定层: 把一次 HTTP 响应归类成"这意味着什么"。

这是整个工具最容易误导人的地方 —— 判错了会让人去换 key、改配置、换站,
而真正的原因可能是 WAF、模型下架、或者渠道把 tool_use 吐成了文本。
所以这一层是**纯函数**: 不读文件、不联网、不发请求, 只吃 (http, 响应体),
因此可以被穷举测试。
"""
import re

BROKEN_TOOL_MARKERS = ('"olls"', '"arguments"', '"input_schema"', '"tool_use"')
# 渠道把工具调用当成文本吐出时, 会留下 pseudo-JSON 碎片(如 cialo 的 {"olls"read"...)。
# 只认 JSON 形状的 name 字段, 不拿单个英文单词当证据。
TOOLCALL_TEXT_RE = re.compile(
    r'["{]\s*"?(?:name|tool|tool_name)"?\s*[":]\s*"?'
    r'(?:read|write|edit|bash|grep|glob|ls|search|fetch|run|exec)\b', re.I)


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
