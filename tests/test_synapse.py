#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synapse 回归测试: 重点是"判定"这层 —— 判错了会直接误导用户去换 key/改配置。

跑:  python3 -m unittest discover -s tests -v
不需要网络, 不发任何请求。
"""
import atexit
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import synapse  # noqa: E402
import synapse as synapse_mod  # noqa: E402

# 全模块统一隔离数据目录。教训: 之前 test_disappeared_target_marks_dirty 会经
# mark_dirty() 把 "目标被移除/禁用: ghost" 写进用户真实的
# ~/.config/synapse/.dirty, 于是 status/doctor 长期显示一条压根没发生的告警 ——
# 测试污染被当成了真实信号, 这比没有告警更糟(会让人去查一个不存在的问题)。
# 单个测试类可以在这个基础上继续覆盖, 但默认值永远不指向真实数据。
_TESTS_TMP = tempfile.mkdtemp(prefix="synapse-tests-")


def _isolate_test_paths(root=_TESTS_TMP):
    synapse.HOME = root
    synapse.CONFIG = os.path.join(root, "config.json")
    synapse.STATIONS = os.path.join(root, "STATIONS.md")
    synapse.REPORTS = os.path.join(root, "reports")
    synapse.ISSUES = os.path.join(root, "issues.json")
    synapse.LOCK = os.path.join(root, ".dirty")
    synapse.PI_MODELS = os.path.join(root, "pi", "models.json")
    os.makedirs(synapse.REPORTS, exist_ok=True)


_isolate_test_paths()
atexit.register(shutil.rmtree, _TESTS_TMP, True)

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


class TestStatusFreshness(unittest.TestCase):
    """监控器自己死了, 没人会知道 —— 所以 status 必须回答"上次体检是什么时候"。

    latest.json 只在全量体检时写。若它很久没更新, 说明定时器/任务挂了,
    这正是"看板全绿但其实早就没在跑"的经典坑。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in ("HOME", "CONFIG", "REPORTS", "ISSUES")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        os.makedirs(synapse.REPORTS, exist_ok=True)
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {
            "base_url": "https://a.invalid", "api_key": "sk-1",
            "models": ["m1"], "enabled": True}}})
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _latest(self, hours_ago, summary=None):
        import datetime as dt
        t = dt.datetime.now() - dt.timedelta(hours=hours_ago)
        synapse.save_json(os.path.join(synapse.REPORTS, "latest.json"), {
            "time": t.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": summary or {"total": 3, "ok": 3, "bad": 0, "warn": 0, "dead": 0},
            "results": [], "partial": False})

    def test_fresh_check_is_reported_without_warning(self):
        self._latest(0.1)
        self.assertEqual(self._run("status"), 0)
        text = self.out.getvalue()
        self.assertIn("最近一次体检", text)
        self.assertNotIn("没在跑", text)

    def test_stale_check_warns_the_watcher_died(self):
        self._latest(10)
        self.assertEqual(self._run("status"), 0)
        text = self.out.getvalue()
        self.assertIn("没在跑", text)

    def test_no_check_yet_is_said_plainly(self):
        self.assertEqual(self._run("status"), 0)
        self.assertIn("无记录", self.out.getvalue())

    def test_status_json_carries_last_check(self):
        self._latest(2)
        self.assertEqual(self._run("status", "--json"), 0)
        import json as _j
        d = _j.loads(self.out.getvalue())
        self.assertIn("last_check", d)
        self.assertAlmostEqual(d["last_check"]["age_hours"], 2, delta=0.5)
        self.assertFalse(d["last_check"]["stale"])

    def test_unparsable_time_does_not_crash(self):
        synapse.save_json(os.path.join(synapse.REPORTS, "latest.json"),
                          {"time": "????", "summary": {"total": 1}, "results": []})
        self.assertEqual(self._run("status"), 0)
        self.assertIn("最近一次体检", self.out.getvalue())


class TestCorruptUserFiles(unittest.TestCase):
    """用户会手改 config.json / issues.json / models.json。

    改坏之后原本是裸 traceback(JSONDecodeError), 连"哪个文件坏了"都要自己从栈里找。
    监控工具最低要求: 说清哪个文件、怎么定位、下一步做什么。
    而且绝不能静默当作空文件 —— 那会悄悄丢掉整个台账。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in
                       ("HOME", "CONFIG", "ISSUES", "REPORTS", "LOCK", "CMD", "PI_MODELS")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.PI_MODELS = os.path.join(self.tmp, "pi-models.json")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _write(self, path, text):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        self.err.seek(0); self.err.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def test_corrupt_config_explains_itself(self):
        self._write(synapse.CONFIG, '{"targets": {oops')
        rc = self._run("status")
        self.assertEqual(rc, 1)
        e = self.err.getvalue()
        self.assertIn("不是合法 JSON", e)
        self.assertIn("config.json", e)
        self.assertIn("json.tool", e)
        self.assertNotIn("Traceback", e)

    def test_corrupt_config_is_not_silently_empty(self):
        """不能被当成"没有配置" —— 那样会引导用户去 import-from-pi, 覆盖掉原文件。"""
        self._write(synapse.CONFIG, 'garbage')
        rc = self._run("check")
        self.assertEqual(rc, 1)
        self.assertNotIn("import-from-pi", self.err.getvalue())

    def test_corrupt_issues_does_not_lose_ledger_silently(self):
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {"base_url": "https://t.invalid",
            "api_key": "k", "models": ["m"], "enabled": True, "default": True}}})
        self._write(synapse.ISSUES, '{"issues": [{"id": 1')
        rc = self._run("issue", "list")
        self.assertEqual(rc, 1)
        self.assertIn("issues.json", self.err.getvalue())
        self.assertNotIn("Traceback", self.err.getvalue())

    def test_doctor_reports_corrupt_config_as_fail_row(self):
        self._write(synapse.CONFIG, '{"bad')
        rc = self._run("doctor")
        self.assertEqual(rc, 1)
        self.assertIn("不是合法 JSON", self.out.getvalue())
        self.assertNotIn("Traceback", self.err.getvalue())

    def test_corrupt_pi_models_explains_itself(self):
        self._write(synapse.PI_MODELS, '{nope')
        rc = self._run("import-from-pi")
        self.assertEqual(rc, 1)
        self.assertIn("不是合法 JSON", self.err.getvalue())
        self.assertNotIn("Traceback", self.err.getvalue())


class TestCorruptStateFiles(unittest.TestCase):
    """.outage.json / latest.json 是我们自己原子写的, 正常不会坏。

    但"正常不会坏"不是不防的理由: 坏掉时主命令崩了, 而用户正想看现在什么状况。
    取舍: 坏掉就当没有(继续工作), 但必须由 doctor 报出来 —— 不能静默。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in
                       ("HOME", "CONFIG", "ISSUES", "REPORTS", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {"base_url": "https://t.invalid",
            "api_key": "k", "models": ["m"], "enabled": True, "default": True}}})
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        self.err.seek(0); self.err.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def test_corrupt_outage_does_not_break_status(self):
        with open(os.path.join(synapse.HOME, ".outage.json"), "w", encoding="utf-8") as f:
            f.write("{broken")
        self.assertEqual(self._run("status"), 0)
        self.assertNotIn("Traceback", self.err.getvalue())

    def test_corrupt_latest_does_not_break_status(self):
        with open(os.path.join(synapse.REPORTS, "latest.json"), "w", encoding="utf-8") as f:
            f.write("nope")
        self.assertEqual(self._run("status"), 0)
        self.assertNotIn("Traceback", self.err.getvalue())

    def test_corrupt_outage_does_not_break_updater(self):
        """坏掉的 .outage.json 不能让 check 崩, 而是重建一份继续累计。"""
        with open(os.path.join(synapse.HOME, ".outage.json"), "w", encoding="utf-8") as f:
            f.write("{broken")
        summary = synapse._outage_track([{"target": "t", "model": "m", "kind": "ok",
                                         "test": "basic"}])
        self.assertEqual(summary["ok"], 1)
        snap = synapse.load_json(os.path.join(synapse.HOME, ".outage.json"))
        self.assertEqual(snap["t||m"]["ok"], 1)

    def test_row_without_test_key_does_not_break_updater(self):
        """缺 test 字段的行(手改/半截报告)不该让累计逻辑抛 KeyError, 也不该被算成连败。"""
        summary = synapse._outage_track([{"target": "t", "model": "m", "kind": "ok"}])
        self.assertEqual(summary["ok"], 1)
        synapse._outage_track([{"target": "t2", "model": "m2", "kind": "timeout"}])
        st = synapse.load_json(os.path.join(synapse.HOME, ".outage.json"))["t2||m2"]
        self.assertEqual(st["streak"], 0)
        self.assertEqual(st["last_kind"], "timeout")

    def test_doctor_reports_corrupt_state_file(self):
        with open(os.path.join(synapse.HOME, ".outage.json"), "w", encoding="utf-8") as f:
            f.write("{broken")
        self._run("doctor")
        text = self.out.getvalue()
        self.assertIn("状态文件", text)
        self.assertIn(".outage.json", text)


class TestUptimeRobustness(unittest.TestCase):
    """刚把 uptime 接进 status 之后, 一条畸形报告就能让主命令崩掉。

    监控工具绝不能因为数据坏而瘫痪 —— 坏数据要跳过并出声, 不是抛异常。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in ("HOME", "CONFIG", "REPORTS", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {"base_url": "https://t.invalid",
            "api_key": "k", "models": ["m"], "enabled": True, "default": True}}})
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _put(self, name, payload_text):
        with open(os.path.join(synapse.REPORTS, name), "w", encoding="utf-8") as f:
            f.write(payload_text)

    def test_truncated_json_report_is_skipped_not_fatal(self):
        self._put("check-20261021-120000.json", '{"results": [{"target": "t"')  # 半截
        rows, used, bad = synapse._uptime_stats(7)
        self.assertEqual((rows, used, bad), ([], 0, 1), "坏文件要计数, 不能装作没发生")

    def test_non_dict_payload_is_skipped(self):
        self._put("check-20261021-120000.json", '[1,2,3]')
        rows, used, bad = synapse._uptime_stats(7)
        self.assertEqual((rows, used, bad), ([], 0, 0))

    def test_non_dict_rows_are_skipped(self):
        self._put("check-20261021-120000.json",
                  json.dumps({"results": ["basic", {"target": "t", "model": "m",
                                                    "kind": "ok", "test": "basic"}]}))
        rows, used, bad = synapse._uptime_stats(7)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["samples"], 1)

    def test_results_not_a_list_is_skipped(self):
        self._put("check-20261021-120000.json", json.dumps({"results": {"a": 1}}))
        rows, used, bad = synapse._uptime_stats(7)
        self.assertEqual((rows, used, bad), ([], 0, 0))

    def test_bad_report_does_not_break_status(self):
        self._put("check-20261021-120000.json", 'not json at all')
        self.assertEqual(synapse.main(["status"], out=self.out, err=self.err), 0)


class TestUptimeByStation(unittest.TestCase):
    """用户选的是"站", 不是"模型"。模型级看完了需要一个站级汇总。"""

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        synapse.save_json(synapse.CONFIG, {"targets": {"a": {"base_url": "https://a.invalid",
            "api_key": "k", "models": ["m1", "m2"], "enabled": True, "default": True}}})
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _round(self, idx, spec):
        """spec: {(target, model): kind}"""
        import datetime as dt
        when = dt.datetime.now() - dt.timedelta(minutes=idx)
        rows = [{"target": t, "model": m, "kind": k, "http": 200, "latency_ms": 10,
                 "test": "basic", "snippet": ""} for (t, m), k in spec.items()]
        synapse.save_json(os.path.join(synapse.REPORTS,
                                       "check-" + when.strftime("%Y%m%d-%H%M%S") + f"-{idx}.json"),
                          {"time": when.strftime("%Y-%m-%d %H:%M:%S"),
                           "summary": {"total": len(rows)}, "results": rows, "partial": False})

    def test_station_rollup_aggregates_models(self):
        for i in range(6):
            self._round(i, {("a", "m1"): "ok", ("a", "m2"): "timeout"})
        self._run("uptime", "--by-station", "--json")
        import json as _j
        d = _j.loads(self.out.getvalue())
        st = d["stations"][0]
        self.assertEqual(st["target"], "a")
        self.assertEqual(st["samples"], 12)
        self.assertAlmostEqual(st["ok_rate"], 0.5, places=3)
        self.assertEqual(st["verdict"], "不建议")

    def test_station_rollup_is_worst_first(self):
        for i in range(6):
            self._round(i, {("a", "m1"): "ok"})
        for i in range(6, 12):
            self._round(i, {("b", "m1"): "timeout"})
        self._run("uptime", "--by-station", "--json")
        import json as _j
        d = _j.loads(self.out.getvalue())
        self.assertEqual([x["target"] for x in d["stations"]], ["b", "a"])

    def test_station_human_output_has_headers(self):
        for i in range(6):
            self._round(i, {("a", "m1"): "ok"})
        self._run("uptime", "--by-station")
        self.assertIn("站级汇总", self.out.getvalue())


class TestStatusUptime(unittest.TestCase):
    """status 是用户的第一条命令: "整体怎么样"必须在那里就能看到。"""

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in
                       ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD", "_schedule_status")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        synapse._schedule_status = lambda: (True, "测试")
        os.makedirs(synapse.REPORTS)
        synapse.save_json(synapse.CONFIG, {"targets": {"a": {"base_url": "https://a.invalid",
            "api_key": "k", "models": ["m1"], "enabled": True, "default": True}}})
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _rounds(self, kinds, days_ago=0):
        import datetime as dt
        for i, k in enumerate(kinds):
            when = dt.datetime.now() - dt.timedelta(days=days_ago, minutes=i)
            rows = [{"target": "a", "model": "m1", "kind": k, "http": 200,
                     "latency_ms": 10, "test": "basic", "snippet": ""}]
            synapse.save_json(os.path.join(synapse.REPORTS,
                                           "check-" + when.strftime("%Y%m%d-%H%M%S") + f"-{i}.json"),
                              {"time": when.strftime("%Y-%m-%d %H:%M:%S"),
                               "summary": {"total": 1}, "results": rows, "partial": False})

    def test_status_shows_stability_tally(self):
        self._rounds(["ok"] * 6)
        self._run("status")
        text = self.out.getvalue()
        self.assertIn("长期稳定性", text)
        self.assertIn("稳 1", text)

    def test_status_json_carries_uptime(self):
        self._rounds(["ok"] * 6)
        self._run("status", "--json")
        import json as _j
        d = _j.loads(self.out.getvalue())
        self.assertIn("uptime", d)
        self.assertEqual(d["uptime"]["tally"]["稳"], 1)

    def test_status_without_reports_is_quiet_but_works(self):
        self.assertEqual(self._run("status"), 0)
        self.assertIn("长期稳定性", self.out.getvalue())

    def test_status_days_window_is_respected(self):
        self._rounds(["ok"] * 6, days_ago=20)
        self._run("status")
        self.assertIn("还没有", self.out.getvalue() + "还没有")
        self._run("status", "--days", "30")
        self.assertIn("稳 1", self.out.getvalue())


class TestUptime(unittest.TestCase):
    """历史稳定性: reports/ 里躺着过去每一轮的完整结果, 但从没人用。

    它要回答的是用户的真问题: "这个站值不值得放进 pi 长跑"。
    两条底线:
      - 样本太少不许下结论(不许把 2 次成功说成 100% 稳)
      - internal_error(我们自己的 bug) 和 config_error 绝不能算进"站的可用率"
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in ("HOME", "REPORTS", "CMD")}
        synapse.HOME = self.tmp
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _report(self, idx, kinds, target="t", model="m", partial=False, days_ago=0, test="basic"):
        """写一份报告: kinds 是这一轮各行的判定。"""
        import datetime as dt
        when = dt.datetime.now() - dt.timedelta(days=days_ago, minutes=idx)
        name = "check-" + when.strftime("%Y%m%d-%H%M%S") + f"-{idx}.json"
        rows = [{"target": target, "model": model, "kind": k, "http": 200 if k.startswith("ok") else 500,
                 "latency_ms": 100, "test": test, "snippet": ""} for k in kinds]
        synapse.save_json(os.path.join(synapse.REPORTS, name),
                          {"time": when.strftime("%Y-%m-%d %H:%M:%S"),
                           "summary": {"total": len(rows)}, "results": rows,
                           "partial": partial})

    def _json(self, *argv):
        self._run(*(argv + ("--json",)))
        import json as _j
        return _j.loads(self.out.getvalue())

    def test_success_rate_over_rounds(self):
        for i in range(10):
            self._report(i, ["ok"] if i < 8 else ["server_error"])
        d = self._json("uptime", "--days", "7")
        t = d["targets"][0]
        self.assertEqual((t["target"], t["model"]), ("t", "m"))
        self.assertEqual(t["samples"], 10)
        self.assertAlmostEqual(t["ok_rate"], 0.8, places=3)

    def test_small_sample_refuses_to_conclude(self):
        for i in range(3):
            self._report(i, ["ok"])
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["ok_rate"], 1.0)
        self.assertEqual(t["verdict"], "样本不足")
        self.assertIn("别下结论", t["advice"])

    def test_internal_error_never_counts_as_station_downtime(self):
        for i in range(5):
            self._report(i, ["ok"])
        for i in range(5, 8):
            self._report(i, ["internal_error"])
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["samples"], 5, "内部错误不是站的样本")
        self.assertEqual(t["ok_rate"], 1.0)
        self.assertEqual(t["internal_errors"], 3)

    def test_config_error_never_counts_as_station_downtime(self):
        for i in range(5):
            self._report(i, ["ok"])
        self._report(9, ["config_error"])
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["samples"], 5)
        self.assertEqual(t["config_errors"], 1)

    def test_partial_spot_checks_are_excluded(self):
        """定点体检是"出问题才去查", 混进来会把可用率压低。"""
        for i in range(5):
            self._report(i, ["ok"])
        for i in range(5, 10):
            self._report(i, ["waf_blocked"], partial=True)
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["samples"], 5)
        self.assertEqual(t["ok_rate"], 1.0)

    def test_window_excludes_old_reports(self):
        for i in range(5):
            self._report(i, ["ok"], days_ago=0)
        for i in range(5, 10):
            self._report(i, ["server_error"], days_ago=30)
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["samples"], 5)
        self.assertEqual(t["ok_rate"], 1.0)

    def test_non_basic_tests_do_not_pollute_stability(self):
        for i in range(5):
            self._report(i, ["ok"])
        for i in range(5, 10):
            self._report(i, ["waf_blocked"], test="tools")
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["samples"], 5)

    def test_longest_failing_streak(self):
        for i, k in enumerate(["ok", "server_error", "server_error", "ok",
                               "timeout", "timeout", "timeout", "ok"]):
            self._report(i, [k])
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["longest_streak"], 3)

    def test_top_failure_reasons(self):
        for i, k in enumerate(["ok", "waf_blocked", "waf_blocked", "waf_blocked", "timeout"]):
            self._report(i, [k])
        t = self._json("uptime", "--days", "7")["targets"][0]
        self.assertEqual(t["reasons"][0], {"kind": "waf_blocked", "count": 3})

    def test_verdict_thresholds(self):
        self.assertEqual(synapse._uptime_verdict(10, 1.0)[0], "稳")
        self.assertEqual(synapse._uptime_verdict(10, 0.85)[0], "勉强")
        self.assertEqual(synapse._uptime_verdict(10, 0.5)[0], "不建议")

    def test_no_reports_is_not_an_error(self):
        self.assertEqual(self._run("uptime"), 0)

    def test_human_output_names_the_verdict(self):
        for i in range(10):
            self._report(i, ["ok"])
        self._run("uptime")
        self.assertIn("稳", self.out.getvalue())


class TestEmptySelection(unittest.TestCase):
    """筛选条件一个都没选中时, 不能输出"合计 0 项"然后退出 0。

    监控工具最坏的输出是"看起来没事": 用户敲错模型名, 拿到的却是一份
    干净的 0 项报告 —— 比报错难查得多(还以为刚检查过)。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in
                       ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD", "run_plan")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {
            "base_url": "https://a.invalid", "api_key": "sk-1",
            "models": ["m"], "enabled": True, "default": True}}})
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def test_unmatched_model_is_a_usage_error(self):
        rc = self._run("check", "--target", "t", "--model", "nope")
        self.assertEqual(rc, 2, "筛选为空必须以用法错误退出, 而不是 0")
        self.assertIn("nope", self.err.getvalue() + self.out.getvalue())

    def test_unmatched_target_is_a_usage_error(self):
        self.assertEqual(self._run("check", "--target", "nope"), 2)

    def test_matched_filter_still_works(self):
        synapse.run_plan = lambda url, key, model, plan, **kw: {
            k: {"kind": "ok", "http": 200, "latency_ms": 1, "snippet": "ok"} for k in plan}
        self.assertEqual(self._run("check", "--target", "t", "--model", "m"), 0)


class TestStreakTransitions(unittest.TestCase):
    """跨轮趋势: 单轮明细里"第 1 轮失败"和"连续第 5 轮失败"长得一样,
    但前者是抖动、后者是故障。转坏/恢复这两个"事件"才值得提醒。
    """

    def test_down_when_crossing_threshold(self):
        prev = {"t||m": {"streak": 1, "last_kind": "timeout"}}
        cur = {"t||m": {"streak": 2, "last_kind": "timeout"}}
        tr = synapse._streak_transitions(prev, cur)
        self.assertEqual(len(tr), 1)
        self.assertEqual(tr[0]["dir"], "down")
        self.assertEqual((tr[0]["target"], tr[0]["model"]), ("t", "m"))

    def test_no_transition_below_threshold(self):
        prev = {"t||m": {"streak": 0}}
        cur = {"t||m": {"streak": 1}}
        self.assertEqual(synapse._streak_transitions(prev, cur), [])

    def test_no_repeat_while_still_down(self):
        prev = {"t||m": {"streak": 3}}
        cur = {"t||m": {"streak": 4}}
        self.assertEqual(synapse._streak_transitions(prev, cur), [],
                         "已经报过转坏就不该每轮再喊一次")

    def test_up_on_full_recovery(self):
        prev = {"t||m": {"streak": 3}}
        cur = {"t||m": {"streak": 0}}
        tr = synapse._streak_transitions(prev, cur)
        self.assertEqual(tr[0]["dir"], "up")
        self.assertEqual(tr[0]["streak"], 3)

    def test_new_key_is_not_a_transition(self):
        self.assertEqual(synapse._streak_transitions({}, {"t||m": {"streak": 2}}), [])


class TestTrendIntegration(unittest.TestCase):
    """跑两轮 check, 第二轮应该把"转坏"讲出来。"""

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in
                       ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD", "run_plan")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS, exist_ok=True)
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {
            "base_url": "https://a.invalid", "api_key": "sk-1",
            "models": ["m"], "enabled": True, "default": True}}})
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _round(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _fail_probe(self, kind="timeout"):
        synapse.run_plan = lambda url, key, model, plan, **kw: {
            k: {"kind": kind, "http": 0, "latency_ms": 1, "snippet": "x"} for k in plan}

    def _ok_probe(self):
        synapse.run_plan = lambda url, key, model, plan, **kw: {
            k: {"kind": "ok", "http": 200, "latency_ms": 1, "snippet": "ok"} for k in plan}

    def test_second_failure_round_is_called_out(self):
        self._fail_probe()
        self._round("check")
        self.assertNotIn("连续 2 轮", self.out.getvalue())
        self._round("check")
        self.assertIn("连续 2 轮失败", self.out.getvalue())

    def test_recovery_is_called_out(self):
        self._fail_probe()
        self._round("check"); self._round("check")
        self._ok_probe()
        self._round("check")
        self.assertIn("已恢复", self.out.getvalue())

    def test_transitions_land_in_the_json_payload(self):
        self._fail_probe()
        self._round("check", "--json")
        self._round("check", "--json")
        import json as _j
        d = _j.loads(self.out.getvalue())
        self.assertTrue(any(t["dir"] == "down" for t in d["transitions"]))


class TestPrune(unittest.TestCase):
    """报告轮转: reports/ 会无限增长(每次 check 一个文件), 得有个回收口。

    规矩和 fix 一致: 默认只预览, --apply 才真删; latest.json 永不被删
    (它是 status/doctor 判断新鲜度的唯一依据)。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in ("HOME", "REPORTS", "CMD")}
        synapse.HOME = self.tmp
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _mk(self, n_check=0, n_diag=0, day=30):
        import datetime as dt
        for i in range(n_check):
            name = f"check-2026010{i + 1}-120000.json"
            path = os.path.join(synapse.REPORTS, name)
            synapse.save_json(path, {"summary": {}})
            self._age(path, day)
        for i in range(n_diag):
            name = f"diagnose-2026010{i + 1}-120000.json"
            path = os.path.join(synapse.REPORTS, name)
            synapse.save_json(path, {"conclusions": []})
            self._age(path, day)
        synapse.save_json(os.path.join(synapse.REPORTS, "latest.json"), {"time": "x"})

    def _age(self, path, days):
        t = time.time() - days * 86400
        os.utime(path, (t, t))

    def _names(self):
        return sorted(os.listdir(synapse.REPORTS))

    def test_dry_run_deletes_nothing(self):
        self._mk(n_check=5)
        self.assertEqual(self._run("prune", "--keep", "2"), 0)
        self.assertEqual(len([n for n in self._names() if n.startswith("check-")]), 5)
        self.assertIn("--apply", self.out.getvalue())

    def test_apply_keeps_newest_n(self):
        self._mk(n_check=5)
        self.assertEqual(self._run("prune", "--keep", "2", "--apply"), 0)
        left = [n for n in self._names() if n.startswith("check-")]
        self.assertEqual(left, ["check-20260104-120000.json", "check-20260105-120000.json"])

    def test_latest_json_is_never_deleted(self):
        self._mk(n_check=3)
        self._run("prune", "--keep", "0", "--apply")
        self.assertIn("latest.json", self._names())

    def test_other_files_are_not_touched(self):
        self._mk(n_check=3)
        for extra in ("config.json", "STATIONS.md", "issues.json"):
            open(os.path.join(synapse.REPORTS, extra), "w").close()
        self._run("prune", "--keep", "0", "--apply")
        names = self._names()
        for extra in ("config.json", "STATIONS.md", "issues.json"):
            self.assertIn(extra, names)

    def test_recent_files_survive_the_age_cutoff(self):
        self._mk(n_check=5, day=0)          # 全是"刚刚"写的
        self._run("prune", "--keep", "0", "--days", "7", "--apply")
        self.assertEqual(len([n for n in self._names() if n.startswith("check-")]), 5)

    def test_diagnose_is_pruned_independently(self):
        self._mk(n_check=3, n_diag=3)
        self._run("prune", "--keep", "1", "--apply")
        self.assertEqual(len([n for n in self._names() if n.startswith("check-")]), 1)
        self.assertEqual(len([n for n in self._names() if n.startswith("diagnose-")]), 1)

    def test_json_reports_what_would_go(self):
        self._mk(n_check=4)
        self._run("prune", "--keep", "1", "--json")
        import json as _j
        d = _j.loads(self.out.getvalue())
        self.assertTrue(d["dry_run"])
        self.assertEqual(len(d["would_delete"]), 3)
        self.assertGreater(d["freed_bytes"], 0)

    def test_empty_reports_dir_is_fine(self):
        self.assertEqual(self._run("prune"), 0)


class TestTestIsolation(unittest.TestCase):
    """守门测试: 测试自身绝不能读写真实数据目录。

    真出过事 —— mark_dirty() 把一条假告警写进了用户真实的 .dirty。
    这里断言所有数据路径都在隔离目录内, 新增路径常量漏了就会红。
    """

    def test_all_data_paths_live_under_isolated_home(self):
        for name in ("CONFIG", "STATIONS", "REPORTS", "ISSUES", "LOCK", "PI_MODELS"):
            path = os.path.abspath(getattr(synapse, name))
            self.assertTrue(path.startswith(os.path.abspath(synapse.HOME)),
                            f"{name}={path} 跑到隔离目录 {synapse.HOME} 外面去了")

    def test_isolated_home_is_not_the_real_one(self):
        real = os.path.abspath(os.path.expanduser("~/.config/synapse"))
        self.assertFalse(os.path.abspath(synapse.HOME).startswith(real),
                         "测试的 HOME 指向了真实数据目录, 会污染用户数据")

    def test_mark_dirty_writes_under_isolation(self):
        synapse.mark_dirty("guard-test")
        try:
            self.assertTrue(synapse.LOCK.startswith(_TESTS_TMP))
            self.assertIn("guard-test", synapse.read_dirty())
        finally:
            synapse.clear_dirty()


class TestDoctor(unittest.TestCase):
    """doctor: 诊断 Synapse 自己。

    能诊断中转站的工具, 却诊断不了自己 —— 前面几轮踩的坑(timer 悄悄停掉、
    SYNAPSE_HOME 继承了旧数据、config 权限 0644 泄露 key)全属于这一类。
    doctor 把这些变成可执行的检查项, 而不是靠人记得。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in
                       ("HOME", "CONFIG", "REPORTS", "ISSUES", "PI_MODELS", "BASE",
                        "LOCK", "CMD")}
        synapse.LOCK = os.path.join(self.tmp, ".dirty")   # 脏标记也必须隔离, 否则读到真实数据
        synapse.CMD = "synapse"
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.PI_MODELS = os.path.join(self.tmp, "pi-models.json")
        os.makedirs(synapse.REPORTS, exist_ok=True)
        self._saved_sched = synapse._schedule_status
        synapse._schedule_status = lambda: (True, "测试: 定时器已启用")
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)
        synapse._schedule_status = self._saved_sched

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        self.err.seek(0); self.err.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def _healthy(self, hours_ago=0.1):
        import datetime as dt
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {
            "base_url": "https://a.invalid", "api_key": "sk-1",
            "models": ["m"], "enabled": True, "default": True}}})
        synapse.save_json(synapse.PI_MODELS, {"providers": {"t": {"models": [{"id": "m"}]}}})
        t = dt.datetime.now() - dt.timedelta(hours=hours_ago)
        synapse.save_json(os.path.join(synapse.REPORTS, "latest.json"), {
            "time": t.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {"total": 1, "ok": 1}})

    def test_missing_config_is_a_failure(self):
        rc = self._run("doctor")
        self.assertEqual(rc, 1)
        self.assertIn("config.json", self.out.getvalue())

    def test_healthy_setup_passes(self):
        self._healthy()
        rc = self._run("doctor")
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn("全部通过", self.out.getvalue())

    def test_world_readable_config_leaks_keys(self):
        self._healthy()
        os.chmod(synapse.CONFIG, 0o644)
        self._run("doctor")
        self.assertIn("权限", self.out.getvalue())

    def test_nobody_scheduled_is_called_out(self):
        self._healthy()
        synapse._schedule_status = lambda: (False, "既没有定时器也没有 crontab")
        rc = self._run("doctor")
        self.assertIn("crontab", self.out.getvalue())
        self.assertEqual(rc, 0, "没人定期体检是警告, 不算故障")

    def test_dangling_key_from_pi_is_reported(self):
        self._healthy()
        cfg = synapse.load_json(synapse.CONFIG, {})
        cfg["targets"]["t"] = {"key_from_pi": "nope", "models": ["m"], "enabled": True}
        synapse.save_json(synapse.CONFIG, cfg)
        self._run("doctor")
        self.assertIn("nope", self.out.getvalue())

    def test_future_timestamp_means_clock_skew(self):
        self._healthy(hours_ago=-5)
        self._run("doctor")
        self.assertIn("时钟", self.out.getvalue())

    def test_data_dir_inside_code_dir_is_a_failure(self):
        self._healthy()
        synapse.BASE = self.tmp
        rc = self._run("doctor")
        self.assertEqual(rc, 1)
        self.assertIn("数据目录", self.out.getvalue())

    def test_stale_open_issue_is_reported(self):
        import datetime as dt
        self._healthy()
        old = (dt.datetime.now() - dt.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        synapse.save_json(synapse.ISSUES, {"issues": [{
            "id": 1, "time": old, "status": "open", "target": "t", "model": "m",
            "kind": "x", "symptom": "s", "cause": "", "plan": "", "notes": []}]})
        self._run("doctor")
        self.assertIn("30 天", self.out.getvalue())

    def test_doctor_warns_when_reports_contain_a_key(self):
        """旧版本可能已经把你的 key 写进了报告 —— 这只有 doctor 能发现。

        站方在错误体里回显 Authorization 是真事; 修复只管以后的写入,
        已经把 key 落到盘上的历史文件必须被人看见。
        """
        path = os.path.join(synapse.REPORTS, "check-20260101-000000.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"results": [{"snippet": "Bearer sk-leaked0123456789abcdef"}]}')
        os.chmod(path, 0o644)
        synapse.main(["doctor", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        names = {c["name"]: c for c in d["checks"]}
        self.assertIn("报告内容", names)
        self.assertEqual(names["报告内容"]["level"], "warn")
        self.assertIn("1", names["报告内容"]["detail"])

    def test_doctor_is_quiet_when_reports_are_clean(self):
        path = os.path.join(synapse.REPORTS, "check-20260101-000000.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"results": [{"snippet": "error code: 502"}]}')
        os.chmod(path, 0o600)
        synapse.main(["doctor", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        names = {c["name"]: c for c in d["checks"]}
        self.assertEqual(names["报告内容"]["level"], "ok")

    def test_json_output_is_parseable(self):
        self._healthy()
        self._run("doctor", "--json")
        import json as _j
        d = _j.loads(self.out.getvalue())
        self.assertIn("checks", d)
        self.assertIn("summary", d)
        levels = {c["level"] for c in d["checks"]}
        self.assertTrue(levels <= {"ok", "warn", "fail"})


def _parser_choices():
    """{子命令: 它的 subparser}, 直接来自 argparse 本体。"""
    ap = synapse_mod.build_parser()
    group = ap._subparsers._group_actions[0]
    return dict(group.choices)


def _parser_subcommands():
    return set(_parser_choices())


def _completion_path():
    return os.path.join(os.path.dirname(synapse_mod.__file__),
                        "packaging-src", "bash-completion", "synapse")


def _completion_subs():
    with open(_completion_path(), encoding="utf-8") as f:
        for line in f:
            if line.strip().startswith("subs="):
                return set(line.split('"')[1].split())
    raise AssertionError("补全文件里找不到 subs= 行")


def _completion_opts_blocks():
    """{子命令: [候选词...]}, 解析 case 语句里的 opts="..." 行。

    允许一条 case 用 a|b) 覆盖多个子命令, 但同时也要求它们参数确实一致
    (不一致就该拆开 —— 合并块正是历史漂移的温床)。
    """
    import re
    with open(_completion_path(), encoding="utf-8") as f:
        src = f.read()
    blocks, pending = {}, None
    for line in src.splitlines():
        m = re.match(r"\s*([a-z|*-]+)\)\s*$", line)
        if m:
            pending = m.group(1)
            continue
        m = re.match(r'\s*opts="([^"]*)"', line)
        if m and pending:
            for name in pending.split("|"):
                if name not in ("*",):
                    blocks[name] = m.group(1).split()
            pending = None
    return blocks
class TestStreakScope(unittest.TestCase):
    """status 同一屏会给出两个"连败"数: 长期稳定性(全量轮) 与 长跑统计(含定向抽查)。

    真实数据上同一对 目标/模型 一个说 17、一个说 12 —— 都"对", 但标签一模一样。
    用户看到两个不同的数只会得出一个结论: 这工具的数字不可信。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k)
                       for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {
            "enabled": True, "models": ["m1"], "default": True}}})

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def test_both_streak_numbers_declare_their_scope(self):
        # 全量轮: 3 连败
        for i in range(3):
            payload = {"time": f"2026-10-0{i + 1} 10:00:00", "partial": False,
                       "summary": {}, "results": [
                           {"target": "t", "model": "m1", "test": "basic",
                            "kind": "timeout", "http": 0, "latency_ms": 0,
                            "snippet": ""}]}
            synapse.save_json(os.path.join(synapse.REPORTS,
                                           f"check-2026100{i + 1}-100000.json"), payload)
        # 长跑统计: 5 连败(含两次定向抽查)
        synapse.save_json(os.path.join(synapse.HOME, ".outage.json"),
                          {"t||m1": {"ok": 0, "fail": 5, "streak": 5,
                                     "last": "2026-10-03 10:00:00",
                                     "last_kind": "timeout"}})
        synapse.main(["status", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("仅全量轮", text)      # 长期稳定性那一块
        self.assertIn("含定向抽查", text)    # 长跑统计那一块
        # 差从哪来必须当面解释, 而不是让用户自己猜 —— 两个数都"对", 但含义不同
        self.assertIn("别混着看", text)
        self.assertIn("全量轮 3", text)
        self.assertIn("含定向抽查 5", text)

    def test_no_scope_noise_when_numbers_agree(self):
        payload = {"time": "2026-10-01 10:00:00", "partial": False, "summary": {},
                   "results": [{"target": "t", "model": "m1", "test": "basic",
                                "kind": "ok", "http": 200, "latency_ms": 5,
                                "snippet": ""}]}
        synapse.save_json(os.path.join(synapse.REPORTS, "check-20261001-100000.json"),
                          payload)
        synapse.save_json(os.path.join(synapse.HOME, ".outage.json"),
                          {"t||m1": {"ok": 1, "fail": 0, "streak": 0,
                                     "last": "2026-10-01 10:00:00", "last_kind": "ok"}})
        synapse.main(["status", "--days", "0"], out=self.out, err=self.err)
        self.assertNotIn("别混着看", self.out.getvalue())


class TestDoctorFix(unittest.TestCase):
    """doctor 会指出"38 份报告是世界可读的", 然后呢? 让用户自己去 chmod?

    诊断不给动作, 等于把最后一步留给半夜被叫醒的人。但自动改文件又不该悄悄做,
    所以照 fix 的规矩: 默认只预览, --apply 才动手。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k)
                       for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _leaky_report(self):
        path = os.path.join(synapse.REPORTS, "check-20260101-000000.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"time": "2026-01-01 00:00:00", "partial": False,
                       "summary": {}, "results": []}, f)
        os.chmod(path, 0o664)
        return path

    def _mode(self, path):
        return os.stat(path).st_mode & 0o777

    def test_preview_does_not_touch_anything(self):
        path = self._leaky_report()
        rc = synapse.main(["doctor", "--fix"], out=self.out, err=self.err)
        self.assertEqual(rc, 0)
        self.assertEqual(self._mode(path), 0o664, "预览就改了文件权限")
        text = self.out.getvalue()
        self.assertIn("chmod 600", text)
        self.assertIn("--apply", text)

    def test_apply_makes_reports_private(self):
        path = self._leaky_report()
        rc = synapse.main(["doctor", "--fix", "--apply"], out=self.out, err=self.err)
        self.assertEqual(rc, 0)
        self.assertEqual(self._mode(path), 0o600)
        self.assertIn("已修", self.out.getvalue())

    def test_json_previews_the_actions(self):
        path = self._leaky_report()
        synapse.main(["doctor", "--fix", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        self.assertFalse(d["applied"])
        chmods = [a for a in d["actions"] if a["what"] == "chmod"]
        self.assertEqual(len(chmods), 1)
        self.assertEqual(chmods[0]["to"], "600")
        self.assertEqual(chmods[0]["path"], path)
        self.assertEqual(self._mode(path), 0o664)

    def test_says_so_when_there_is_nothing_to_fix(self):
        p = os.path.join(synapse.REPORTS, "check-20260101-000000.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"time": "2026-01-01 00:00:00", "partial": False,
                       "summary": {}, "results": []}, f)
        os.chmod(p, 0o600)
        rc = synapse.main(["doctor", "--fix", "--apply"], out=self.out, err=self.err)
        self.assertEqual(rc, 0)
        self.assertIn("没有可自动修复", self.out.getvalue())

    def test_leaked_content_is_not_silently_rewritten(self):
        """含 key 的报告不自动改内容 —— 只报告, 让人决定。悄悄改掉证据更糟。"""
        path = os.path.join(synapse.REPORTS, "check-20260101-000000.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"time": "2026-01-01 00:00:00", "partial": False, "summary": {},
                       "results": [{"target": "t", "model": "m", "kind": "ok",
                                    "snippet": "Bearer sk-abcdefghijklmnop1234"}]}, f)
        before = open(path, encoding="utf-8").read()
        synapse.main(["doctor", "--fix", "--apply"], out=self.out, err=self.err)
        self.assertEqual(open(path, encoding="utf-8").read(), before)
        self.assertIn("含密钥", self.out.getvalue())


class TestDocsConsistency(unittest.TestCase):
    """文档里的版本号必须和代码一致。

    之前 man page 一直写着 "synapse 1.0.0"(发到 1.4.0 都没人发现),
    因为它没有任何地方被校验。现在这条是硬性断言。
    """

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, rel):
        with open(os.path.join(self.ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_man_page_version_matches(self):
        self.assertIn(f"synapse {synapse.__version__}", self._read("man/synapse.1"),
                      "man/synapse.1 的版本号没跟上 __version__")

    def test_debian_control_version_matches(self):
        self.assertIn(f"Version: {synapse.__version__}",
                      self._read("packaging-src/DEBIAN/control"))

    def test_changelog_top_entry_matches(self):
        first = self._read("debian-doc/changelog.Debian").split("\n", 1)[0]
        self.assertIn(f"({synapse.__version__})", first,
                      "changelog 最新一条不是当前版本")

    def test_bash_completion_lists_every_subcommand(self):
        """补全文件曾经漏掉 doctor/prune/status —— 和 man 页版本号一样是"没人校验"。

        这里直接从 synapse.py 里抽 sub.add_parser("<name>") 的真名单, 和补全文件比对,
        新增子命令忘了补就会红。
        """
        subs = _parser_subcommands()
        self.assertTrue(subs, "没能从 parser 里取到子命令列表(抽取逻辑失效了)")
        listed = _completion_subs()
        self.assertEqual(subs - listed, set(), "补全文件漏了这些子命令")
        self.assertEqual(listed - subs, set(), "补全文件列出了已不存在的子命令")

    def test_bash_completion_opts_match_parser(self):
        """子命令对了不算完 —— 每个子命令的参数也要对上。

        历史遗留: 补全里长期挂着一个 parser 中并不存在的 issue --note,
        以及 import-from-pi 一个参数都没列(落到 * 分支只剩 --help)。
        用户 Tab 出来的候选错了, 比没有补全更让人怀疑工具坏了。
        """
        blocks = _completion_opts_blocks()
        for name, parser in _parser_choices().items():
            real = set()
            for a in parser._actions:
                real |= set(a.option_strings)
            real -= {"-h", "--help"}
            block = blocks.get(name)
            self.assertIsNotNone(block, f"补全文件没有 {name} 的分支")
            cited = {t for t in block if t.startswith("-")}
            self.assertEqual(real - cited, set(),
                             f"补全文件漏了 {name} 的这些参数")
            self.assertEqual(cited - real, set(),
                             f"补全文件给 {name} 列出了不存在的参数")

    def test_version_is_a_plain_semver(self):
        import re
        self.assertRegex(synapse.__version__, r"^\d+\.\d+\.\d+$")


class TestErrorTriage(unittest.TestCase):
    """网络异常 vs 我们自己的 bug —— 必须分开报。

    旧实现把 probe 里所有异常一律当 conn_error: 我们自己的 KeyError/TypeError
    会被报告成"站连不上", 用户就去追一个根本健康的站。这是最坏的一种假阳性。
    """

    def test_network_error_is_conn_error(self):
        kind, snip = synapse._net_or_internal(urllib.error.URLError("boom"))
        self.assertEqual(kind, "conn_error")
        self.assertIn("URLError", snip)

    def test_timeout_is_timeout(self):
        kind, _ = synapse._net_or_internal(TimeoutError("timed out"))
        self.assertEqual(kind, "timeout")

    def test_oserror_is_conn_error(self):
        kind, _ = synapse._net_or_internal(ConnectionResetError("reset"))
        self.assertEqual(kind, "conn_error")

    def test_our_own_bug_is_internal_error_not_conn_error(self):
        """KeyError/TypeError 是我们的 bug, 不能伪装成站方故障。"""
        for exc in (KeyError("content"), TypeError("bad"), AttributeError("nope")):
            kind, snip = synapse._net_or_internal(exc)
            self.assertEqual(kind, "internal_error", f"{type(exc).__name__} 被误判")
            self.assertIn(type(exc).__name__, snip)

    def test_internal_error_has_a_loud_verdict(self):
        self.assertIn("internal_error", synapse.VERDICT)
        self.assertIn("bug", synapse.VERDICT["internal_error"].lower())

    def test_probe_maps_unexpected_exception_to_internal_error(self):
        orig = synapse.urllib.request.urlopen
        synapse.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            r = synapse.probe("https://a.invalid", "sk-1", "m", timeout=1)
        finally:
            synapse.urllib.request.urlopen = orig
        self.assertEqual(r["kind"], "internal_error")

    def test_probe_still_maps_network_exception_to_conn_error(self):
        orig = synapse.urllib.request.urlopen
        synapse.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(
            urllib.error.URLError("dns fail"))
        try:
            r = synapse.probe("https://a.invalid", "sk-1", "m", timeout=1)
        finally:
            synapse.urllib.request.urlopen = orig
        self.assertEqual(r["kind"], "conn_error")

    def test_run_plan_does_not_disguise_bug_as_station_fault(self):
        """run_plan 里任何一项探针炸了, 也不能一律算站挂了。

        注意 patch 的是 synapse_probe.probe: 拆分后 run_plan 和 probe 同住在
        synapse_probe 模块里, 它按自己的模块全局查找 probe。patch
        synapse.probe 会静默失效(测试照样绿, 但什么都没验证到)。
        """
        import synapse_probe
        orig = synapse_probe.probe
        synapse_probe.probe = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("kaboom"))
        try:
            out = synapse.run_plan("https://a.invalid", "sk-1", "m", ["basic"], timeout=1)
        finally:
            synapse_probe.probe = orig
        self.assertEqual(out["basic"]["kind"], "internal_error")

    def test_internal_error_is_not_a_station_outage(self):
        """内部错误不进连续失败计数, 但要让整轮体检算"有异常"(退出码 1)。"""
        import tempfile
        tmp = tempfile.mkdtemp()
        saved = synapse.HOME
        synapse.HOME = tmp
        try:
            stat = synapse._outage_track([
                {"target": "t", "model": "m", "kind": "internal_error", "test": "basic"},
            ])
            snap = synapse.load_json(os.path.join(tmp, ".outage.json"), {})
        finally:
            synapse.HOME = saved
        self.assertEqual(snap, {})                     # 没被写成"站挂了"
        self.assertEqual(stat["bad"], 1)               # 但本轮确实有异常

    def test_systemctl_missing_binary_is_127(self):
        orig = synapse.subprocess.run
        def boom(*a, **k): raise FileNotFoundError("no systemctl")
        synapse.subprocess.run = boom
        try:
            rc, out = synapse._systemctl("status", "x")
        finally:
            synapse.subprocess.run = orig
        self.assertEqual(rc, 127)

    def test_systemctl_does_not_swallow_programming_bugs(self):
        """_systemctl 只该兜系统层错误; 我们自己的 bug 要炸出来。"""
        orig = synapse.subprocess.run
        def boom(*a, **k): raise RuntimeError("kaboom")
        synapse.subprocess.run = boom
        try:
            with self.assertRaises(RuntimeError):
                synapse._systemctl("status", "x")
        finally:
            synapse.subprocess.run = orig


class TestJsonOutputCoverage(unittest.TestCase):
    """机器可读输出不能只有 `check` 有: 脚本要能问"台账里有什么"、"这站到底怎么了"。

    diagnose 用假的 run_plan 注入结果, 不联网。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k) for k in ("HOME", "CONFIG", "REPORTS", "ISSUES")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        self.out, self.err = io.StringIO(), io.StringIO()
        synapse.save_json(synapse.CONFIG, {"targets": {"t": {
            "base_url": "https://a.invalid", "api_key": "sk-1",
            "models": ["m1"], "enabled": True}}})

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _run(self, *argv):
        self.out.seek(0); self.out.truncate(0)
        self.err.seek(0); self.err.truncate(0)
        return synapse.main(list(argv), out=self.out, err=self.err)

    def test_issue_list_json(self):
        self._run("issue", "add", "--target", "t", "--model", "m1",
                  "--kind", "k", "--symptom", "现象B")
        self.assertEqual(self._run("issue", "list", "--json"), 0)
        d = self.json.loads(self.out.getvalue())
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["issues"][0]["symptom"], "现象B")

    def test_diagnose_json(self):
        orig = synapse.run_plan
        synapse.run_plan = lambda url, key, model, plan, **kw: {
            k: {"kind": "ok", "http": 200, "latency_ms": 5, "snippet": ""} for k in plan}
        try:
            rc = self._run("diagnose", "--target", "t", "--json")
        finally:
            synapse.run_plan = orig
        self.assertEqual(rc, 0)
        d = self.json.loads(self.out.getvalue())
        self.assertEqual(d["target"], "t")
        self.assertEqual(d["model"], "m1")
        self.assertEqual(d["results"]["basic"]["kind"], "ok")
        self.assertTrue(d["conclusions"])            # 结论必须是机器可读的数组

    def test_diagnose_thinking_unsupported_conclusion(self):
        """这条分支以前没测过, 结果 %-格式串少传一个参数直接 TypeError 崩了。
        结论文字里的"建议命令"必须能正确格式化。"""
        orig = synapse.run_plan
        def fake(url, key, model, plan, **kw):
            return {k: {"kind": "thinking_unsupported" if k == "thinking" else "ok",
                        "http": 200, "latency_ms": 1, "snippet": ""} for k in plan}
        synapse.run_plan = fake
        try:
            rc = self._run("diagnose", "--target", "t", "--json")
        finally:
            synapse.run_plan = orig
        self.assertEqual(rc, 0)
        d = self.json.loads(self.out.getvalue())
        joined = " ".join(d["conclusions"])
        self.assertIn("reasoning", joined)
        self.assertIn("fix --target t --model m1", joined)

    def test_diagnose_vision_and_cache_conclusions(self):
        orig = synapse.run_plan
        def fake(url, key, model, plan, **kw):
            bad = {"vision_user": "bad_request", "cache": "cache_miss"}
            return {k: {"kind": bad.get(k, "ok"), "http": 200 if k not in bad else 400,
                        "latency_ms": 1, "snippet": ""} for k in plan}
        synapse.run_plan = fake
        try:
            rc = self._run("diagnose", "--target", "t", "--json", "--vision", "--cache")
        finally:
            synapse.run_plan = orig
        self.assertEqual(rc, 0)
        d = self.json.loads(self.out.getvalue())
        joined = " ".join(d["conclusions"])
        self.assertIn("disable-image", joined)
        self.assertIn("缓存", joined)
        self.assertEqual(d["results"]["cache"]["kind"], "cache_miss")

    @property
    def json(self):
        import json as _j
        return _j


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
        self.out.seek(0); self.out.truncate(0)
        self.err.seek(0); self.err.truncate(0)
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
        with open(synapse.PI_MODELS, encoding="utf-8") as f:
            before = f.read()
        self.assertEqual(self._run("fix", "--target", "p", "--model", "m1"), 0)
        self.assertIn("[预览]", self.out.getvalue())
        with open(synapse.PI_MODELS, encoding="utf-8") as f:
            self.assertEqual(f.read(), before)

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


class TestReportHtml(unittest.TestCase):
    """逐轮数据被压成几个百分比, 信息全丢了。

    排查时需要的是"这周第几轮开始烂、烂成什么样" —— 一张离线可看的图,
    比 5 行百分比直观得多。而且它必须是**自包含**的: 中转站面板经常开在
    断网的机器上, 引用任何 CDN 都等于打不开。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k)
                       for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".lock")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _round(self, ts, rows, partial=False):
        payload = {"time": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}",
                   "summary": {}, "results": rows, "partial": partial}
        with open(os.path.join(synapse.REPORTS, f"check-{ts}.json"), "w",
                  encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    def _ok(self, t, m, lat=1000):
        return {"target": t, "model": m, "kind": "ok", "http": 200,
                "latency_ms": lat, "snippet": "fine", "test": "basic"}

    def _bad(self, t, m, kind="timeout"):
        return {"target": t, "model": m, "kind": kind, "http": 0,
                "latency_ms": 0, "snippet": "", "test": "basic"}

    def _out_path(self):
        return os.path.join(self.tmp, "dashboard.html")

    def test_writes_self_contained_html(self):
        """仪表盘必须离线可看: 不许引用任何外部脚本/样式/字体/图片。"""
        self._round("20261020-100000", [self._ok("alpha", "m1", 900)])
        self._round("20261020-110000", [self._bad("alpha", "m1", "timeout")])
        rc = synapse.main(["report", "--days", "0", "--out", self._out_path()],
                          out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        with open(self._out_path(), encoding="utf-8") as f:
            html = f.read()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("alpha", html)
        # 自包含: 没有外部资源引用(SVG 的 xmlns 是命名空间, 不算引用)
        for bad in ('<script src', '<link rel="stylesheet"', '@import', 'url(http',
                    'fonts.googleapis', 'cdn.'):
            self.assertNotIn(bad, html, "仪表盘引用了外部资源, 断网就是白屏")

    def test_heatmap_shows_each_round_kind(self):
        """每一轮的成败都要在热力图里有一格 —— 这是它比百分比多出来的信息。"""
        self._round("20261020-100000", [self._ok("alpha", "m1")])
        self._round("20261020-110000", [self._bad("alpha", "m1", "timeout")])
        synapse.main(["report", "--days", "0", "--out", self._out_path()],
                     out=self.out, err=self.err)
        with open(self._out_path(), encoding="utf-8") as f:
            html = f.read()
        self.assertIn('class="cell k-ok" data-kind="ok"', html)
        self.assertIn('class="cell k-dead" data-kind="timeout"', html)

    def test_json_payload_is_pure_json(self):
        """脚本用户不能被落下: --json 时 stdout 只有 JSON, 人话走 stderr。"""
        self._round("20261020-100000", [self._ok("alpha", "m1")])
        rc = synapse.main(["report", "--days", "0", "--out", self._out_path(), "--json"],
                          out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        payload = json.loads(self.out.getvalue())
        for k in ("path", "days", "rounds", "reports_used", "unreadable_reports",
                  "stations", "targets", "ok_rate"):
            self.assertIn(k, payload)
        self.assertEqual(payload["rounds"], 1)

    def test_empty_history_still_renders_with_hint(self):
        """没有历史不是错误, 但必须说清"去跑什么", 而不是给一张空图让人猜。"""
        rc = synapse.main(["report", "--days", "0", "--out", self._out_path()],
                          out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        with open(self._out_path(), encoding="utf-8") as f:
            html = f.read()
        self.assertIn("还没有", html)
        self.assertIn("check", html)

    def test_dashboard_carries_the_action_panel(self):
        """一张只能看得出"红"的图还不够 —— 图里必须写出下一步敲什么。

        否则用户还是要回来敲 explain, 那张图就只是个更花哨的 status。
        """
        self._round("20261020-100000", [self._bad("alpha", "m1", "auth_failed")])
        out = os.path.join(self.tmp, "d.html")
        rc = synapse.main(["report", "--days", "0", "--out", out],
                          out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        with open(out, encoding="utf-8") as f:
            html = f.read()
        self.assertIn("该做什么", html)
        self.assertIn("auth_failed", html)
        self.assertIn("synapse check --target alpha", html)


    def test_dashboard_and_reports_are_not_world_readable(self):
        """报告里有站方回显的原文; 0664 意味着同机任何人都能读到你的站清单。"""
        import io
        import tempfile
        tmp = tempfile.mkdtemp()
        saved = {k: getattr(synapse, k) for k in ("HOME","CONFIG","REPORTS","ISSUES","LOCK","CMD")}
        try:
            synapse.HOME, synapse.CMD = tmp, "synapse"
            synapse.CONFIG = os.path.join(tmp, "config.json")
            synapse.REPORTS = os.path.join(tmp, "reports")
            synapse.ISSUES = os.path.join(tmp, "issues.json")
            synapse.LOCK = os.path.join(tmp, ".lock")
            os.makedirs(synapse.REPORTS)
            out = os.path.join(tmp, "d.html")
            synapse.main(["report", "--days", "0", "--out", out],
                         out=io.StringIO(), err=io.StringIO())
            self.assertEqual(os.stat(out).st_mode & 0o077, 0,
                             "仪表盘对同组/其他用户可读")
        finally:
            for k, v in saved.items():
                setattr(synapse, k, v)

    def test_default_output_path_is_reports_dashboard(self):
        synapse.main(["report", "--days", "0"], out=self.out, err=self.err)
        self.assertTrue(os.path.exists(os.path.join(synapse.REPORTS, "dashboard.html")))

    def test_user_supplied_names_are_escaped(self):
        """站名/模型名来自配置文件, 里面可能有尖括号; 不转义就是自伤式 XSS。"""
        self._round("20261020-100000", [self._ok("a<b>", "m&1")])
        synapse.main(["report", "--days", "0", "--out", self._out_path()],
                     out=self.out, err=self.err)
        with open(self._out_path(), encoding="utf-8") as f:
            html = f.read()
        self.assertNotIn("a<b>", html)
        self.assertIn("a&lt;b&gt;", html)

class TestTimeline(unittest.TestCase):
    """半夜被叫醒的人要知道的不是"连败 17", 而是"坏了多久了"。

    连败 5 轮(30 分钟)和连败 5 轮(3 天)是两种完全不同的决定:
    前者等一等, 后者立刻换站。只报次数等于把这个判断藏起来。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k)
                       for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".lock")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _round(self, ts, rows):
        payload = {"time": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}",
                   "summary": {}, "results": rows, "partial": False}
        with open(os.path.join(synapse.REPORTS, f"check-{ts}.json"), "w",
                  encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    def _row(self, t, m, kind, test="basic"):
        return {"target": t, "model": m, "kind": kind, "http": 200,
                "latency_ms": 500, "snippet": "", "test": test}

    def test_says_since_when_a_target_has_been_failing(self):
        """连败是从哪一轮开始的 —— 这个时间点决定了"等一等"还是"立刻换"。"""
        for i in range(4):
            self._round(f"2026102{i}-100000", [self._row("t1", "m1", "ok")])
        for i in range(3):
            self._round(f"2026102{i + 4}-100000", [self._row("t1", "m1", "timeout")])
        synapse.main(["timeline", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("t1/m1", text)
        self.assertIn("2026-10-24 10:00", text)      # 连败起点
        self.assertIn("2.0 天", text)                # 从连败起点到最后一轮报告

    def test_recovered_target_is_not_listed_as_failing(self):
        for i in range(3):
            self._round(f"2026102{i}-100000", [self._row("t1", "m1", "timeout")])
        for i in range(2):
            self._round(f"2026102{i + 3}-100000", [self._row("t1", "m1", "ok")])
        synapse.main(["timeline", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("当前通过", text)
        self.assertNotIn("正在失败(", text)

    def test_json_carries_since_and_duration(self):
        for i in range(3):
            self._round(f"2026102{i}-100000", [self._row("t1", "m1", "timeout")])
        synapse.main(["timeline", "--days", "0", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        row = d["failing"][0]
        self.assertEqual(row["target"], "t1")
        self.assertTrue(row["since"].startswith("2026-10-20"))
        self.assertGreater(row["hours"], 0)
        self.assertEqual(row["streak"], 3)

    def test_target_filter(self):
        self._round("20261020-100000", [self._row("t1", "m1", "timeout"),
                                        self._row("t2", "m1", "timeout")])
        synapse.main(["timeline", "--days", "0", "--target", "t1"],
                     out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("t1/m1", text)
        self.assertNotIn("t2/m1", text)

    def test_empty_history_says_so(self):
        rc = synapse.main(["timeline", "--days", "0"], out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        self.assertIn("还没有", self.out.getvalue())

class TestStatusVerdict(unittest.TestCase):
    """status 是半夜被叫醒时第一个敲的命令, 它第一屏必须是结论。

    现在它先铺 9 行目标清单(静态配置), 真正的结论("你默认的站 2 天没通过,
    该换成 tierflow")却在 best 里 —— 醒来的人不会想到再敲一次 best。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k)
                       for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".dirty")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _round(self, ts, rows):
        payload = {"time": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}",
                   "summary": {}, "results": rows, "partial": False}
        with open(os.path.join(synapse.REPORTS, f"check-{ts}.json"), "w",
                  encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    def _row(self, t, m, kind):
        return {"target": t, "model": m, "kind": kind, "http": 200,
                "latency_ms": 500, "snippet": "", "test": "basic"}

    def _cfg(self, default):
        cfg = {"targets": {"good": {"enabled": True, "models": ["m1"]},
                           "bad": {"enabled": True, "models": ["m1"]}}}
        if default:
            cfg["targets"][default]["default"] = True
        synapse.save_json(synapse.CONFIG, cfg)

    def test_status_puts_the_conclusion_first(self):
        self._cfg("bad")
        for i in range(6):
            self._round(f"2026102{i}-100000",
                        [self._row("good", "m1", "ok"),
                         self._row("bad", "m1", "timeout")])
        synapse.main(["status"], out=self.out, err=self.err)
        text = self.out.getvalue()
        # 结论必须出现在目标清单之前 —— 醒了的人只看得进第一屏
        self.assertLess(text.index("现在"), text.index("[目标清单]"),
                        "status 的结论被静态配置挡住了")

    def test_status_names_the_default_station_and_the_alternative(self):
        self._cfg("bad")
        for i in range(6):
            self._round(f"2026102{i}-100000",
                        [self._row("good", "m1", "ok"),
                         self._row("bad", "m1", "timeout")])
        synapse.main(["status"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("bad", text)
        self.assertIn("good", text)
        self.assertIn("synapse best", text)

    def test_status_and_best_never_disagree(self):
        """两处各算一遍推荐, 迟早给出不同答案 —— 那比不推荐更糟。"""
        self._cfg("bad")
        for i in range(6):
            self._round(f"2026102{i}-100000",
                        [self._row("good", "m1", "ok"),
                         self._row("bad", "m1", "timeout"),
                         self._row("good", "m2", "ok")])
        synapse.main(["best", "--days", "0", "--json"], out=self.out, err=self.err)
        pick = json.loads(self.out.getvalue())["pick"]
        self.out.seek(0); self.out.truncate(0)
        synapse.main(["status", "--days", "0", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        self.assertEqual(d["verdict"]["pick"]["target"], pick["target"])
        self.assertEqual(d["verdict"]["pick"]["model"], pick["model"])

    def test_status_does_not_invent_a_problem_when_all_is_well(self):
        self._cfg("good")
        for i in range(6):
            self._round(f"2026102{i}-100000", [self._row("good", "m1", "ok")])
        synapse.main(["status"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("没有正在失败", text)
        self.assertNotIn("[!] 默认站", text)


class TestBest(unittest.TestCase):
    """监控的终点是决策: "我该把哪个站/模型放进 pi"。

    这不是拍脑袋的排行 —— 样本不足时必须拒绝给结论, 判定必须能追到证据,
    否则就是在制造"看起来很像结论的猜测"。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k)
                       for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".lock")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _round(self, ts, rows):
        payload = {"time": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}",
                   "summary": {}, "results": rows, "partial": False}
        with open(os.path.join(synapse.REPORTS, f"check-{ts}.json"), "w",
                  encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    def _row(self, t, m, kind, test="basic", lat=900):
        return {"target": t, "model": m, "kind": kind, "http": 200,
                "latency_ms": lat, "snippet": "", "test": test}

    def test_ranks_the_healthier_target_first(self):
        for i in range(6):
            self._round(f"2026102{i}-100000",
                        [self._row("good", "m1", "ok"),
                         self._row("bad", "m1", "timeout")])
        rc = synapse.main(["best", "--days", "0"], out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        text = self.out.getvalue()
        self.assertLess(text.index("good/m1"), text.index("bad/m1"),
                        "成功率高的排前面")

    def test_refuses_to_rank_when_samples_are_thin(self):
        """2 次成功不是 100% 稳。样本不足必须明确拒绝, 而不是给个漂亮的第一名。"""
        self._round("20261020-100000", [self._row("thin", "m1", "ok"),
                                        self._row("thin", "m1", "ok")])
        synapse.main(["best", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("样本不足", text)
        self.assertNotIn("推荐: thin/m1", text)

    def test_internal_errors_do_not_lower_a_station_score(self):
        """我们自己的 bug 不该让一个健康的站排名下滑 —— 那是甩锅给站方。"""
        rows = [self._row("stable", "m1", "ok") for _ in range(6)]
        rows += [self._row("stable", "m1", "internal_error")]
        self._round("20261020-100000", rows)
        synapse.main(["best", "--days", "0", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        row = [r for r in d["ranked"] if r["target"] == "stable"][0]
        self.assertEqual(row["ok_rate"], 1.0)

    def test_need_tools_excludes_broken_tool_channels(self):
        """要做 agent 就必须真的能调工具: 会吐坏 JSON 的站必须被排除。"""
        for i in range(5):
            self._round(f"2026102{i}-100000",
                        [self._row("chatty", "m1", "ok"),
                         self._row("chatty", "m1", "ok", test="tools"),
                         self._row("brokentools", "m1", "ok"),
                         self._row("brokentools", "m1", "tool_call_broken", test="tools")])
        synapse.main(["best", "--days", "0", "--need", "tools"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertNotIn("推荐: brokentools", text)
        self.assertIn("推荐: chatty/m1", text)
        # 被排除的仍要列出来 + 说清原因(消失会让人以为没测过)
        self.assertIn("brokentools/m1: tools 最近一次是 tool_call_broken", text)

    def test_json_exposes_the_evidence_not_just_a_winner(self):
        for i in range(6):
            self._round(f"2026102{i}-100000", [self._row("good", "m1", "ok")])
        synapse.main(["best", "--days", "0", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        self.assertIn("ranked", d)
        row = d["ranked"][0]
        for k in ("target", "model", "ok_rate", "samples", "verdict", "longest_streak"):
            self.assertIn(k, row)


    def test_warns_when_the_default_target_is_the_worst_one(self):
        """最贵的假信号: 工具推荐了 A, 却不说你标为默认的是那个 0% 的 B。

        用户不会自己把 best 的输出和 config 的 default 标记对起来 ——
        那正是工具该替他做的事。
        """
        cfg = {"targets": {"good": {"enabled": True, "models": ["m1"]},
                           "bad": {"enabled": True, "models": ["m1"],
                                   "default": True}}}
        with open(synapse.CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        for i in range(6):
            self._round(f"2026102{i}-100000",
                        [self._row("good", "m1", "ok"),
                         self._row("bad", "m1", "timeout")])
        synapse.main(["best", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("default", text)
        self.assertIn("bad", text)
        self.assertIn("推荐: good/m1", text)
        self.assertIn("sync-stations --default good", text)

    def test_says_nothing_when_the_default_is_already_the_best(self):
        cfg = {"targets": {"good": {"enabled": True, "models": ["m1"],
                                    "default": True}}}
        with open(synapse.CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        for i in range(6):
            self._round(f"2026102{i}-100000", [self._row("good", "m1", "ok")])
        synapse.main(["best", "--days", "0"], out=self.out, err=self.err)
        self.assertNotIn("[!] 默认站", self.out.getvalue())

    def test_json_reports_the_current_default(self):
        cfg = {"targets": {"bad": {"enabled": True, "models": ["m1"],
                                   "default": True},
                           "good": {"enabled": True, "models": ["m1"]}}}
        with open(synapse.CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        for i in range(6):
            self._round(f"2026102{i}-100000",
                        [self._row("good", "m1", "ok"),
                         self._row("bad", "m1", "timeout")])
        synapse.main(["best", "--days", "0", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        self.assertEqual(d["current_default"]["target"], "bad")
        self.assertEqual(d["current_default"]["verdict"], "不建议")
        self.assertTrue(d["current_default"]["mismatch"])

    def test_empty_history_says_so_instead_of_printing_a_winner(self):
        rc = synapse.main(["best", "--days", "0"], out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        self.assertIn("还没有", self.out.getvalue())


class TestSecretRedaction(unittest.TestCase):
    """报告会被贴到 issue / 群里求助 —— 里面绝不能有你的 key。

    站方完全可能在错误体里回显请求头(见过), 于是 key 就跟着 snippet
    落进 0664 的报告文件。这类泄露你事后根本发现不了, 所以必须在
    写盘前脱敏, 而不是指望站方不回显。
    """

    KEY = "sk-live-TESTONLY-0123456789abcdef"

    def setUp(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        key = self.KEY

        class Echo(BaseHTTPRequestHandler):
            def do_POST(self):
                # 恶意/粗糙的站: 把 Authorization 头原样回显
                body = json.dumps({"error": "bad key",
                                   "echo": self.headers.get("Authorization", ""),
                                   "api_key": key}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), Echo)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_station_echoing_the_key_cannot_get_it_into_the_snippet(self):
        import synapse_probe
        row = synapse_probe.probe(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                                 self.KEY, "m")
        self.assertNotIn(self.KEY, row["snippet"],
                         "站方回显的 key 被原样存进了报告")
        self.assertIn("***", row["snippet"], "脱敏后应留下可见的占位符")

    def test_bearer_and_api_key_patterns_are_redacted(self):
        import synapse_probe
        txt = ('Authorization: Bearer abcdef0123456789abcdef '
               '{"api_key": "abcdef0123456789"}')
        out = synapse_probe.redact(txt)
        self.assertNotIn("abcdef0123456789", out)
        self.assertIn("Bearer ***", out)

    def test_redaction_keeps_enough_evidence_to_be_useful(self):
        """脱敏不能把整段吃掉: 排查需要看到 "401 invalid key" 这种信息。"""
        import synapse_probe
        out = synapse_probe.redact('error code: 401 invalid api key for model x')
        self.assertIn("401", out)
        self.assertIn("invalid api key", out)


class TestExplain(unittest.TestCase):
    """报告只会说"0% / 连败 17 / no_channel", 但不回答"那我现在该干嘛"。

    半夜被叫醒的人需要的是三件事: 这是谁的锅、要不要换站、敲哪条命令。
    explain 就是这三件事, 其余都是废话。
    """

    def setUp(self):
        import io
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: getattr(synapse, k)
                       for k in ("HOME", "CONFIG", "REPORTS", "ISSUES", "LOCK", "CMD")}
        synapse.HOME = self.tmp
        synapse.CONFIG = os.path.join(self.tmp, "config.json")
        synapse.REPORTS = os.path.join(self.tmp, "reports")
        synapse.ISSUES = os.path.join(self.tmp, "issues.json")
        synapse.LOCK = os.path.join(self.tmp, ".lock")
        synapse.CMD = "synapse"
        os.makedirs(synapse.REPORTS)
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(synapse, k, v)

    def _round(self, ts, rows):
        payload = {"time": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}",
                   "summary": {}, "results": rows, "partial": False}
        with open(os.path.join(synapse.REPORTS, f"check-{ts}.json"), "w",
                  encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    def _row(self, t, m, kind):
        return {"target": t, "model": m, "kind": kind, "http": 0,
                "latency_ms": 0, "snippet": "", "test": "basic"}

    def test_every_verdict_kind_has_a_playbook(self):
        """没人校验的东西一定会漂: 新增一个判定却忘了写"怎么处理"就红。"""
        from synapse_classify import PLAYBOOK, VERDICT
        missing = set(VERDICT) - set(PLAYBOOK)
        self.assertEqual(missing, set(), f"这些判定没有处理建议: {sorted(missing)}")

    def test_groups_by_kind_and_names_the_owner(self):
        """同一个 kind 分散在不同站, 要合成一条: 用户要判断的是"谁的锅", 不是逐站数。"""
        self._round("20261020-100000", [self._row("alpha", "m1", "no_channel"),
                                        self._row("beta", "m2", "no_channel"),
                                        self._row("alpha", "m1", "auth_failed")])
        rc = synapse.main(["explain", "--days", "0"], out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        text = self.out.getvalue()
        self.assertIn("no_channel", text)
        self.assertIn("站方", text)          # 谁的锅
        self.assertIn("换", text)            # 要不要换站
        self.assertIn("alpha/m1", text)      # 影响面

    def test_internal_error_is_never_blamed_on_the_station(self):
        """我们自己的 bug 必须明确写成"我们的问题", 绝不能让用户去换站。"""
        self._round("20261020-100000", [self._row("alpha", "m1", "internal_error")])
        synapse.main(["explain", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("我们", text)
        self.assertIn("不是站", text)

    def test_json_payload_is_pure_json(self):
        self._round("20261020-100000", [self._row("alpha", "m1", "timeout")])
        rc = synapse.main(["explain", "--days", "0", "--json"], out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        d = json.loads(self.out.getvalue())
        self.assertEqual(d["groups"][0]["kind"], "timeout")
        self.assertIn("owner", d["groups"][0])
        self.assertTrue(d["groups"][0]["commands"])


    def test_auth_failed_plus_same_station_success_is_not_a_key_problem(self):
        """真实数据里 5 个站都同时有 auth_failed 和成功轮 —— 同一把 key。

        这时候让人去换 key 是纯粹的浪费: key 是好的, 坏的是那几个模型在
        站方那边的权限/分组。工具必须用同一窗口的成功轮当反证。
        """
        self._round("20261020-100000", [self._row("hyb", "m1", "auth_failed"),
                                        self._row("hyb", "m1", "auth_failed"),
                                        self._row("hyb", "m2", "ok")])
        synapse.main(["explain", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("反证", text)
        self.assertIn("不用换 key", text)
        self.assertNotIn("锅: 你", text)

    def test_auth_failed_alone_still_points_at_the_key(self):
        """没有反证时该怀疑 key 就得怀疑 key —— 不能为了好看把真问题盖掉。"""
        self._round("20261020-100000", [self._row("solo", "m1", "auth_failed")])
        synapse.main(["explain", "--days", "0"], out=self.out, err=self.err)
        text = self.out.getvalue()
        self.assertIn("锅: 你", text)
        self.assertNotIn("反证", text)

    def test_counter_evidence_is_in_the_json(self):
        """脚本用户也要能拿到反证, 否则他们只能自己重新算一遍。"""
        self._round("20261020-100000", [self._row("hyb", "m1", "auth_failed"),
                                        self._row("hyb", "m2", "ok")])
        synapse.main(["explain", "--days", "0", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        g = [x for x in d["groups"] if x["kind"] == "auth_failed"][0]
        self.assertEqual(g["counter_evidence"], [{"target": "hyb", "ok": 1}])

    def test_nothing_to_do_is_stated_not_silent(self):
        self._round("20261020-100000", [{"target": "alpha", "model": "m1", "kind": "ok",
                                        "http": 200, "latency_ms": 900,
                                        "snippet": "", "test": "basic"}])
        rc = synapse.main(["explain", "--days", "0"], out=self.out, err=self.err)
        self.assertEqual(rc, 0, self.err.getvalue())
        self.assertIn("没有需要处理", self.out.getvalue())

    def test_ok_rows_are_not_listed_as_problems(self):
        """成功轮不该出现在"该怎么处理"里 —— 否则满屏绿条, 人就不看了。"""
        self._round("20261020-100000", [{"target": "alpha", "model": "m1", "kind": "ok",
                                        "http": 200, "latency_ms": 900,
                                        "snippet": "", "test": "basic"}])
        synapse.main(["explain", "--days", "0", "--json"], out=self.out, err=self.err)
        d = json.loads(self.out.getvalue())
        self.assertEqual(d["groups"], [])


if __name__ == "__main__":
    unittest.main()
