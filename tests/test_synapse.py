#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synapse 回归测试: 重点是"判定"这层 —— 判错了会直接误导用户去换 key/改配置。

跑:  python3 -m unittest discover -s tests -v
不需要网络, 不发任何请求。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import synapse  # noqa: E402

WAF_HTML = ("<!DOCTYPE html><html lang=\"zh\"><head><title>访问已被拦截</title>"
            "<meta charset=\"utf-8\"></head><body>您的访问已被拦截</body></html>")
API_401 = '{"error":{"message":"invalid api key","type":"authentication_error"}}'
MODEL_404 = '{"error":{"message":"model_not_found","type":"model_not_found"}}'


class TestClassify(unittest.TestCase):
    """classify() 的优先级: WAF > 无渠道 > 鉴权 > ..."""

    def test_403_html_is_waf_not_auth(self):
        """403 + HTML 拦截页 = WAF, 不能报 'key无效'(曾经的真 bug)。"""
        self.assertEqual(synapse.classify(403, WAF_HTML, False), "waf_blocked")

    def test_403_json_is_auth(self):
        """403 + JSON 鉴权错误 才是真鉴权失败。"""
        self.assertEqual(synapse.classify(403, API_401, False), "auth_failed")

    def test_401_json_is_auth(self):
        self.assertEqual(synapse.classify(401, API_401, False), "auth_failed")

    def test_cloudflare_marker_any_status(self):
        self.assertEqual(synapse.classify(503, "error code: 1010", False), "waf_blocked")
        self.assertEqual(synapse.classify(200, "Just a moment...", False), "waf_blocked")

    def test_model_not_found_is_no_channel_not_5xx(self):
        """503 + model_not_found = 模型名不对, 不是'上游渠道不稳'。"""
        self.assertEqual(synapse.classify(503, MODEL_404, False), "no_channel")

    def test_no_channel_marker(self):
        self.assertEqual(synapse.classify(400, '{"message":"该分组无可用渠道"}', False),
                         "no_channel")

    def test_anti_probe(self):
        self.assertEqual(synapse.classify(400, "检测到测活请求", False), "anti_probe")

    def test_thinking_and_upstream_400(self):
        self.assertEqual(synapse.classify(400, "upstream error: thinking unsupported", True),
                         "thinking_unsupported")
        self.assertEqual(synapse.classify(400, "upstream error: bad param", False),
                         "upstream_400")
        self.assertEqual(synapse.classify(400, "invalid value for temperature", False),
                         "bad_request")

    def test_auth_unavailable(self):
        self.assertEqual(synapse.classify(503, '{"error":{"code":"auth_unavailable"}}', False),
                         "auth_unavailable")

    def test_rate_limit_and_500(self):
        self.assertEqual(synapse.classify(429, "too many requests", False), "rate_limited")
        self.assertEqual(synapse.classify(502, "bad gateway", False), "server_error")

    def test_unknown_status(self):
        self.assertEqual(synapse.classify(418, "teapot", False), "http_418")


class TestVerdictCoverage(unittest.TestCase):
    """classify 可能返回的每个 kind 都必须有中文判定文本, 否则终端里会漏出英文码。"""

    def test_all_kinds_have_verdict(self):
        kinds = [
            "ok", "ok_truncated", "ok_nonjson", "ok_tool_use", "tool_call_text",
            "tool_call_broken", "cache_passthrough", "cache_miss", "auth_failed",
            "waf_blocked", "no_channel", "anti_probe", "thinking_unsupported",
            "upstream_400", "bad_request", "auth_unavailable", "rate_limited",
            "server_error", "timeout", "conn_error",
        ]
        for k in kinds:
            self.assertIn(k, synapse.VERDICT, f"VERDICT 缺少 {k}")


class TestIssueDedup(unittest.TestCase):
    """自动开单去重: 同 target+model+kind 在窗口内只能有一条未关单。"""

    def setUp(self):
        self.db = {"issues": []}

    def test_same_issue_merges(self):
        nid1, created1 = synapse.issue_add_auto(
            self.db, "t", "m", "稳定性(挂死/5xx)", "超时")
        nid2, created2 = synapse.issue_add_auto(
            self.db, "t", "m", "稳定性(挂死/5xx)", "又超时")
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(nid1, nid2)
        self.assertEqual(len(self.db["issues"]), 1)
        self.assertEqual(len(self.db["issues"][0]["notes"]), 1)

    def test_different_kind_is_separate(self):
        synapse.issue_add_auto(self.db, "t", "m", "稳定性(挂死/5xx)", "超时")
        _, created = synapse.issue_add_auto(self.db, "t", "m", "WAF拦截", "拦截")
        self.assertTrue(created)
        self.assertEqual(len(self.db["issues"]), 2)

    def test_closed_issue_not_reused(self):
        self.db["issues"].append({"id": 1, "time": synapse.now(), "status": "fixed",
                                  "target": "t", "model": "m", "kind": "k",
                                  "symptom": "x", "notes": []})
        nid, created = synapse.issue_add_auto(self.db, "t", "m", "k", "y")
        self.assertTrue(created)
        self.assertEqual(nid, 2)


QUIET = lambda *a, **k: None   # 测试里别把台账提示打到控制台


class TestAutoRecover(unittest.TestCase):
    """自愈: 全量体检变好 → 先记一笔, 连续两轮 → 自动结单。手工单不碰。"""

    def setUp(self):
        self.saved = 0
        self._orig = (synapse.load_issues, synapse.save_issues)

        def fake_save(db):
            self.saved += 1

        synapse.save_issues = fake_save
        self.rows_ok = [{"target": "t", "model": "m", "test": "basic",
                         "kind": "ok"}]
        self.rows_bad = [{"target": "t", "model": "m", "test": "basic",
                          "kind": "timeout"}]

    def tearDown(self):
        synapse.load_issues, synapse.save_issues = self._orig

    def _db(self, kind="WAF/CDN拦截", auto=True, status="open", model="m"):
        return {"issues": [{"id": 1, "time": synapse.now(), "status": status,
                            "target": "t", "model": model, "kind": kind,
                            "symptom": "x", "notes": [], "auto": auto}]}

    def test_first_recovery_only_notes(self):
        db = self._db()
        n = synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        self.assertEqual(n, 1)
        self.assertEqual(db["issues"][0]["status"], "open")
        self.assertIn("[恢复]", db["issues"][0]["notes"][0]["text"])

    def test_second_recovery_closes(self):
        db = self._db()
        synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        self.assertEqual(db["issues"][0]["status"], "fixed")

    def test_still_bad_does_nothing(self):
        db = self._db()
        self.assertEqual(synapse._auto_recover_from_rows(self.rows_bad, db, say=QUIET), 0)
        self.assertEqual(db["issues"][0]["notes"], [])

    def test_manual_issue_never_touched(self):
        db = self._db(auto=False)
        synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        self.assertEqual(db["issues"][0]["status"], "open")
        self.assertEqual(db["issues"][0]["notes"], [])

    def test_non_transient_kind_never_closed(self):
        """agent 工具链路损坏这种不是“恢复就好”的, 不能自动结单。"""
        db = self._db(kind="agent工具调用被破坏")
        synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        self.assertEqual(db["issues"][0]["status"], "open")

    def test_station_level_issue_recovers_on_any_ok(self):
        db = self._db(model="")           # WAF 站级单
        synapse._auto_recover_from_rows(self.rows_ok, db, say=QUIET)
        self.assertEqual(len(db["issues"][0]["notes"]), 1)


class TestToolJudge(unittest.TestCase):
    """_judge_tool_resp: 判错方向很致命 —— 误报 tool_call_broken 会让用户
    把一个好好的站当成“不能跑 agent”而弃用。
    铁律: 只有看到**JSON 碎片**才能判 broken, 不能因为正文里出现某个英文单词。"""

    @staticmethod
    def _text(t):
        return {"content": [{"type": "text", "text": t}]}

    def test_tool_use_block_is_ok(self):
        body = {"content": [{"type": "tool_use", "id": "toolu_1",
                            "name": "bash", "input": {"command": "ls"}}]}
        self.assertEqual(synapse._judge_tool_resp("ok", body, "", "")[0], "ok_tool_use")

    def test_plain_prose_with_read_is_not_broken(self):
        """正文里出现 read 这个单词就判 broken 是旧 bug。"""
        for prose in ("I have already read the file and it looks fine.",
                      "Please read the docs before continuing.",
                      "Already read it."):
            kind, _ = synapse._judge_tool_resp("ok", self._text(prose), "", "")
            self.assertNotEqual(kind, "tool_call_broken", prose)

    def test_plain_prose_with_arguments_is_not_broken(self):
        """arguments / input_schema 在正常英文里也会出现。"""
        for prose in ("Let me pass the arguments to the function.",
                      "The arguments are invalid.",
                      "input schema looks fine"):
            kind, _ = synapse._judge_tool_resp("ok", self._text(prose), "", "")
            self.assertNotEqual(kind, "tool_call_broken", prose)

    def test_real_corruption_is_broken(self):
        """cialo 实测的那种坏 JSON 碎片必须识别出来。"""
        for bad in ('{"olls"read":{"path":"/tmp/a"}}',
                    '{"name":"read","arguments":{"path":"/tmp/a"}}',
                    'call {"tool_use": {"name": "read"}}'):
            kind, _ = synapse._judge_tool_resp("ok", self._text(bad), "", "")
            self.assertEqual(kind, "tool_call_broken", bad)

    def test_normal_text_is_text_not_broken(self):
        self.assertEqual(synapse._judge_tool_resp("ok", self._text("42"), "", "")[0],
                         "tool_call_text")

    def test_no_text_no_tool_keeps_kind(self):
        self.assertEqual(synapse._judge_tool_resp("ok_truncated", {"content": []}, "", "")[0],
                         "ok_truncated")


class TestAtomicWrite(unittest.TestCase):
    """config.json 里是明文的 API key —— 写一半就崩会让用户丢配置。"""

    def test_write_is_atomic_and_valid(self):
        import json as _json
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "config.json")
        synapse.save_json(p, {"a": 1, "中文": "值"})
        with open(p, encoding="utf-8") as f:
            self.assertEqual(_json.load(f), {"a": 1, "中文": "值"})

    def test_old_content_survives_failed_write(self):
        """序列化失败时, 旧文件必须原封不动(不能先清空再写)。"""
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "config.json")
        synapse.save_json(p, {"keep": "me"})
        with self.assertRaises(TypeError):
            synapse.save_json(p, {"bad": object()})
        with open(p, encoding="utf-8") as f:
            self.assertIn("keep", f.read())

    def test_written_file_is_private(self):
        """含密钥的文件不应该给别人读。"""
        import stat as _stat
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "config.json")
        synapse.save_json(p, {"api_key": "sk-x"})
        mode = _stat.S_IMODE(os.stat(p).st_mode)
        self.assertEqual(mode & 0o077, 0, oct(mode))


class TestTargetsOf(unittest.TestCase):
    """targets_of 是“哪些站会被检查”的唯一入口, 它默默吞掉的站就等于报告里不存在。"""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._home = synapse.HOME
        synapse.HOME = self.tmp
        self.cfg = {"targets": {
            "good": {"base_url": "https://a.dev", "api_key": "sk-1",
                     "enabled": True, "models": ["m1", "m2"]},
            "off": {"base_url": "https://b.dev", "api_key": "sk-2",
                    "enabled": False, "models": ["m1"]},
            "nokey": {"base_url": "https://c.dev", "enabled": True, "models": ["m1"]},
        }}

    def tearDown(self):
        synapse.HOME = self._home

    class A:
        target = None
        model = None

    def test_disabled_and_filtering(self):
        out = synapse.targets_of(self.cfg, self.A())
        names = [r[0] for r in out]
        self.assertIn("good", names)
        self.assertNotIn("off", names)          # 停用的不查

    def test_model_filter(self):
        class A2:
            target = None
            model = "m2"
        out = synapse.targets_of(self.cfg, A2())
        good = [r for r in out if r[0] == "good"][0]
        self.assertEqual(good[3], ["m2"])

    def test_broken_target_is_reported_not_dropped(self):
        """缺 key 的站必须留下一个标记(models=None), 不能静默变成一个不存在的目标。"""
        out = synapse.targets_of(self.cfg, self.A())
        bad = [r for r in out if r[0] == "nokey"]
        self.assertEqual(len(bad), 1)
        self.assertIsNone(bad[0][3])

    def test_config_error_row_renders_as_failure(self):
        row = synapse._config_error_row("nokey", "[!] 目标 nokey 缺少 base_url 或 api_key")
        self.assertEqual(row["kind"], "config_error")
        self.assertIn("config_error", synapse.VERDICT)
        self.assertEqual(row["target"], "nokey")
        self.assertFalse(row["snippet"].startswith("[!]"), row["snippet"])

    def test_snapshot_is_written(self):
        synapse.targets_of(self.cfg, self.A())
        snap = synapse.load_json(os.path.join(self.tmp, ".targets_snapshot.json"))
        self.assertEqual(sorted(snap), ["good", "nokey"])

    def test_disappeared_target_marks_dirty(self):
        synapse.save_json(os.path.join(self.tmp, ".targets_snapshot.json"),
                          ["good", "nokey", "ghost"])
        synapse.targets_of(self.cfg, self.A())
        self.assertTrue(synapse.read_dirty())


class TestCli(unittest.TestCase):
    """端到端跑 main(), 输出流注入 StringIO。

    这一层以前完全没法测(cmd_* 直接 print + sys.exit),
    结果"输出到底去了哪"这种最基本的事只能靠人肉看。它现在就钉住:
      - --json 时 stdout 必须是纯 JSON(人类可读走 stderr)
      - 退出码要能区分 正常/异常/配置缺失
      - fix 不加 --apply 绝不写盘
    """

    def setUp(self):
        import io
        import json as _json
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in
                       ("HOME", "CONFIG", "STATIONS", "REPORTS", "ISSUES", "PI_MODELS")}
        h = self.tmp
        synapse.HOME = h
        synapse.CONFIG = os.path.join(h, "config.json")
        synapse.STATIONS = os.path.join(h, "STATIONS.md")
        synapse.REPORTS = os.path.join(h, "reports")
        synapse.ISSUES = os.path.join(h, "issues.json")
        synapse.PI_MODELS = os.path.join(h, "models.json")
        self.json = _json
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.truncate(0); self.err.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _config(self, targets):
        synapse.save_json(synapse.CONFIG, {"targets": targets})

    def test_version_exits_zero(self):
        self.assertEqual(self._run("--version"), 0)

    def test_missing_config_is_a_clean_error(self):
        rc = self._run("check")
        self.assertEqual(rc, 1)
        self.assertEqual(self.out.getvalue(), "")          # stdout 不留垃圾
        self.assertIn("import-from-pi", self.err.getvalue())

    def test_check_json_stdout_is_pure_json(self):
        """只有配置错误的目标 → 不用联网就能验证 JSON 契约。"""
        self._config({"bad": {"base_url": "https://a.invalid", "models": ["m"]}})
        rc = self._run("check", "--json")
        self.assertEqual(rc, 1)                            # 有异常项
        data = self.json.loads(self.out.getvalue())        # 必须可解析, 没有表格混进来
        self.assertEqual(data["results"][0]["kind"], "config_error")
        self.assertIn("合计", self.err.getvalue())          # 人话走了 stderr

    def test_check_without_json_prints_table_to_stdout(self):
        self._config({"bad": {"base_url": "https://a.invalid", "models": ["m"]}})
        self.assertEqual(self._run("check"), 1)
        self.assertIn("配置不完整", self.out.getvalue())

    def test_status_json_is_pure_json(self):
        self._config({"t": {"base_url": "https://a.invalid", "api_key": "sk-1",
                            "models": ["m"], "enabled": True}})
        self.assertEqual(self._run("status", "--json"), 0)
        data = self.json.loads(self.out.getvalue())
        self.assertIn("t", data["targets"])

    def test_issue_add_then_list(self):
        self._config({})
        self.assertEqual(self._run("issue", "add", "--target", "x", "--model", "m",
                                   "--kind", "测试", "--symptom", "现象A"), 0)
        self.assertEqual(self._run("issue", "list"), 0)
        self.assertIn("现象A", self.out.getvalue())

    def test_fix_without_apply_never_writes(self):
        """--apply 是用户的明确授权; 不加就绝对不能碰 pi 的配置。"""
        self._config({})
        synapse.save_json(synapse.PI_MODELS, {"providers": {"p": {"apiKey": "sk-1",
                       "baseUrl": "https://a.invalid",
                       "models": [{"id": "m1", "reasoning": True}]}}})
        before = open(synapse.PI_MODELS, encoding="utf-8").read()
        self.assertEqual(self._run("fix", "--target", "p", "--model", "m1"), 0)
        self.assertIn("[预览]", self.out.getvalue())
        self.assertEqual(open(synapse.PI_MODELS, encoding="utf-8").read(), before)

    def test_fix_apply_writes_and_backs_up(self):
        self._config({})
        synapse.save_json(synapse.PI_MODELS, {"providers": {"p": {"apiKey": "sk-1",
                       "baseUrl": "https://a.invalid",
                       "models": [{"id": "m1", "reasoning": True}]}}})
        self.assertEqual(self._run("fix", "--target", "p", "--model", "m1",
                                   "--apply"), 0)
        after = self.json.load(open(synapse.PI_MODELS, encoding="utf-8"))
        self.assertFalse(after["providers"]["p"]["models"][0]["reasoning"])
        backups = [f for f in os.listdir(self.tmp) if "models.json" in f and "bak" in f]
        self.assertTrue(backups, "必须留备份")

    def test_unknown_target_in_fix_is_clean_error(self):
        self._config({})
        synapse.save_json(synapse.PI_MODELS, {"providers": {}})
        self.assertEqual(self._run("fix", "--target", "nope", "--model", "m"), 1)
        self.assertIn("没有 provider", self.err.getvalue())


class TestStationsParser(unittest.TestCase):
    """STATIONS.md 解析: 只认 SYNC 区, pi: 引用不算 URL, #off 停用。"""

    def _parse(self, text):
        import tempfile
        fd, p = tempfile.mkstemp(suffix=".md")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            return synapse.parse_stations(p)
        finally:
            os.remove(p)

    def test_only_sync_block_parsed(self):
        rows = self._parse(
            "# t\n\n| 名字 | Base URL | API Key | 模型 |\n"
            "|---|---|---|---|\n"
            "| 说明假行 | https://no.pe | sk-x | m1 |\n\n"
            "<!-- SYNC:BEGIN -->\n"
            "| 名字 | Base URL | API Key | 模型 |\n|---|---|---|---|\n"
            "| real | https://a.dev | sk-abc | glm-5.3，deepseek |\n"
            "<!-- SYNC:END -->\n")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "real")
        self.assertEqual(rows[0]["models"], ["glm-5.3", "deepseek"])

    def test_pi_ref_blank_url(self):
        rows = self._parse("<!-- SYNC:BEGIN -->\n| n | Base URL | API Key | 模型 |\n"
                           "|---|---|---|---|\n| hyb | pi:hyb | pi:hyb | m |\n"
                           "<!-- SYNC:END -->\n")
        self.assertEqual(rows[0]["base_url"], "")

    def test_off_marker(self):
        rows = self._parse("<!-- SYNC:BEGIN -->\n| n | Base URL | API Key | 模型 |\n"
                           "|---|---|---|---|\n| dead | https://d.dev | sk-1 | m #off |\n"
                           "<!-- SYNC:END -->\n")
        self.assertFalse(rows[0]["enabled"])
        self.assertEqual(rows[0]["models"], ["m"])


if __name__ == "__main__":
    unittest.main()
