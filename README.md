# Synapse

pi 模型中转站的连通性监控 / 诊断 / 配置修复工具。
原则：**探测一律只读；`~/.pi/agent/models.json` 只有在你明确下令（`fix --apply`）时才会被修改，且每次修改自动备份。**

## 文件

| 文件 | 说明 |
|---|---|
| **`STATIONS.md`** | **你维护的中转站清单（URL / key / 模型）——新站就加这里** |
| `synapse.py` | 主程序：CLI / 状态 / 台账 / 配置；无第三方依赖（纯标准库） |
| `synapse_classify.py` | 判定层：把一次响应归类成"这意味着什么"（纯函数，可穷举测试） |
| `synapse_probe.py` | 探测层：真正发请求的地方（只读，异常要分诊） |
| `config.json` | 由 `sync-stations` 从 STATIONS.md 生成的目标清单（手改会被覆盖） |
| `reports/latest.json` | 最近一次 check 的完整结果（每次 check 同时按时间戳落盘） |
| `.outage.json` | 长跑失败统计（每 `目标\|\|模型` 的 ok/fail/连败轮数），由 `check` 自动累加，`status` 消费 |

> 📦 **注意**：以上数据文件都在**数据目录**（`~/.config/synapse/`，可用环境变量 `SYNAPSE_HOME` 覆盖）。
> 源码目录里若还有旧数据文件，首次运行会自动复制迁移过去，原文件保留。
> 装 Debian 包后命令就是 `synapse`（不再需要 `python3 synapse.py`）。

### 数据文件坏了会怎样

监控工具不能因为数据坏就瘫掉，也不能装作没发生。三类文件区别对待：

| 文件 | 损坏时 |
|---|---|
| 用户配置（`config.json` / `issues.json` / pi `models.json`） | **报错退出（码 1）**，并打印 `python3 -m json.tool <路径>` 让你定位。静默当空配置会假装“一切正常”，比报错危险得多 |
| 历史状态（`.outage.json` / `latest.json`） | 按“没有历史”继续跑，但 `doctor` 的「状态文件」一项会点名 -> 统计从零开始这件事必须可见 |
| 历史报告（`reports/*.json`） | `uptime` / `status` 跳过并计数，摘要写“另有 N 份报告无法读取（已跳过）”，一条坏文件不会毁掉其余统计 |

## 加中转站：只改 `STATIONS.md`

在 `STATIONS.md` 的表格里加一行（要么直接填 url+key，要么 `pi:provider` 复用 pi 已配的），然后：

```bash
python3 synapse.py sync-stations              # STATIONS.md → config.json
python3 synapse.py sync-stations --check       # 同步 + 立刻全量体检
python3 synapse.py sync-stations --log         # 把体检摘要回写 STATIONS.md
```

`sync-stations` 只写 `config.json`，**永远不动 pi 的 `models.json`**。

## Debian 软件包

```bash
bash build-deb.sh                          # 出 dist/synapse_<版本>_all.deb
sudo dpkg -i dist/synapse_1.1.0_all.deb     # 安装
man synapse                                # 手册
sudo dpkg -r synapse                       # 卸载（用户数据 ~/.config/synapse 保留）
```

包内容：代码进 `/usr/lib/synapse/`、入口壳 `/usr/bin/synapse`、man 手册、
bash 补全、changelog/copyright、systemd 用户单元。
**用户数据全部留在 `~/.config/synapse/`**（FHS 合规，升级不丢数据）。
构建前会自动清点，绝不让密钥/数据文件混进包里。

### 定时体检：用 systemd 而不是 crontab

```bash
synapse timer on --interval 1h             # 启用（登录后自动拉起，每小时一轮）
synapse timer on --interval 30min --now     # 改间隔 + 立刻跑一轮
synapse timer status                       # 下次触发时间
synapse timer run                          # 立即触发（后台，不阻塞终端）
synapse timer log                          # journalctl 最近 50 行
synapse timer off                          # 停用
```

为什么用 timer：不依赖登录 shell 的 PATH/环境，能看结构化日志，
机器重启后会按 `timers.target` 自动恢复；错过一轮不会扎堆补跑。
无 systemd 的环境（容器）用 `synapse cron --install` 退回 crontab。

## 正视现状（先看这个）

```bash
python3 synapse.py status          # 一览: 目标清单 + 长跑失败统计 + 未解决台账
```

`status` 会把「哪些模型连续失败」直接点出来，并给出「临时禁用」建议（`status` 不改配置，只是提示）。
长跑统计由每次 `check` 累加到 `.outage.json`；失败判定以每模型的 `basic` 项为准。

### 怎么判断一个站能不能进 pi 的 agent 流程

| 想干什么 | 看哪个测试 | 门槛 |
|---|---|---|
| 纯聊天 | `check`（basic） | ✅ 正常即可 |
| 跑 agent / 用工具 | `check --tools` | 必须是 `ok_tool_use`；`tool_call_text` 勉强、`tool_call_broken`/`timeout` 不行 |
| 省钱（长会话） | `check --cache` | `cache_passthrough` 才省钱 |
| 让 pi 看图（read 工具） | `check --vision` | `toolResult` 形态也要 ✅ |
| 长跑稳定性 | `watch` + `status` | 连败 ≥2 轮就该停用 |

### 长期稳定性（该不该把这个站放进长跑）

```bash
python3 synapse.py uptime --days 7
```

```
  目标/模型                                    样本     成功率     最长连败     p50  判定
  hyb/deepseek-v4.1-flash                  17    0.0%       17       -  不建议
                                         └ 主要失败: server_error×12, auth_failed×4
  tierflow/tierflow                        20  100.0%        0    1.9s  稳
```

单轮检查只能告诉你"此刻通不通"，`uptime` 把历史报告聚合成成功率。
`status` 里也有一份 `[长期稳定性]` 摘要（判定计数 + 最差的几条），所以第一条命令
就能看到"这周整体稳不稳"；`--by-station` 按站汇总，因为用户选的是站不是模型。
两条底线：**样本少于 5 次拒绝下结论**（2 次成功不是 100% 稳）；
`internal_error`（Synapse 自己的 bug）、`config_error`（配置没写全）和
`partial` 定点体检**都不计入可用率** —— 它们会让一个健康的站看起来很差。

`check` 每轮会自己讲**趋势**：某个 `目标/模型` 连败到第 2 轮时打一行
`[趋势] ... 连续 2 轮失败 → 不是偶发抖动`，恢复时打 `[趋势] ... 已恢复`。
同一件事只报一次（不会每轮重复喊），所以单轮抖动和持续性故障一眼可分。

## 常用命令

```bash
# 一次性全量连通性检查（并发，结果打印 + 存 reports/）
python3 synapse.py check -v

# 机读模式：只出一份 JSON（time/summary/results），方便接别的脚本
# 人类可读的表格会自动走 stderr，所以管道里只剩纯 JSON
python3 synapse.py check --json | jq '.summary'

# 长期稳定性: 过去 N 天每个站到底稳不稳(样本不足会拒绝下结论)
python3 synapse.py uptime                    # 默认看最近 7 天
python3 synapse.py uptime --days 30
python3 synapse.py uptime --target hyb --json | jq '.targets[0]'
python3 synapse.py uptime --by-station     # 站级汇总(用户选的是站, 不是模型)

# 报告回收: reports/ 每轮一个文件会无限长，默认只预览，--apply 才真删
python3 synapse.py prune                       # 默认保留每类最新 200 个、且只删 7 天前的
python3 synapse.py prune --keep 50 --days 3    # 更激进（仍只预览）
python3 synapse.py prune --keep 50 --apply     # 真删（latest.json 永不删）

# 全局一览: 目标清单 / 长跑失败统计(.outage.json) / 未解决台账
python3 synapse.py status
python3 synapse.py status --json          # 机读版
python3 synapse.py status --stale-hours 2  # 超过 2h 没全量体检就告警(默认 3)

# 诊断"这个工具自己": 数据目录位置/权限、定时器是否还活着、时钟、台账陈旧度
python3 synapse.py doctor
python3 synapse.py doctor --json | jq '.summary'   # {"ok":7,"warn":2,"fail":0}

# 机器可读输出不止 check: 脚本要能问"这站到底怎么了"、"台账里有什么"
python3 synapse.py diagnose --target hyb --model z-ai/glm-5.3 --json | jq '.conclusions'
python3 synapse.py issue list --json | jq '.open'

# 只查某个目标 / 某个模型
python3 synapse.py check --target hyb --model z-ai/glm-5.3 -v

# 带工具调用测试 🔧 —— 抓“纯聊天能用、跑 agent 就崩”的坏站
# （cialo 就是此类：带 tools 必超时，或把 tool_use 吐成坏 JSON 文本）
python3 synapse.py check --tools -v

# 带前缀缓存测试 💰 —— 看站方是否透传 prompt cache（两侧直连直出）
# 不透传的站，pi 长会话每轮全价重算（issue#3 就是这个）
python3 synapse.py check --cache

# 异常自动写入问题台账（同日同因去重，不会刷屏）
python3 synapse.py check --tools --auto-issue

# 前台常驻监控，每 5 分钟一轮（可加 --tools / --vision / --cache 每轮都测）
python3 synapse.py watch --interval 300

# 单模型深度诊断：基础 / 流式 / 工具 / 工具结构 / thinking 五项
# （pi 里最常见的 400 upstream_error 就是 thinking 参数被上游拒绝）
python3 synapse.py diagnose --target hyb --model z-ai/glm-5.3

# 诊断时附图像两项，并用真实图片（比内置色块更能验证“看得懂”）
python3 synapse.py diagnose --target cialo --model glm-5.2 --vision \
    --image-file ~/pictures/background/2026-05-10_19-28-14.png

# 诊断时附前缀缓存项
python3 synapse.py diagnose --target tierflow --model tierflow --cache

# 修复 pi 配置：默认只【预览】diff，不写盘
python3 synapse.py fix --target hyb --model z-ai/glm-5.3 --fix disable-reasoning
# 确认无误、下令执行时加 --apply（自动备份 models.json）
python3 synapse.py fix --target hyb --model z-ai/glm-5.3 --fix disable-reasoning --apply

# 连通性检查 + 图像输入能力测试（🖼 标记的行）
python3 synapse.py check --vision

# 定期任务（可选）：写入 crontab，每小时自动 check
python3 synapse.py cron --schedule "0 * * * *" --install

# 从 pi 的 models.json 重新导入/同步目标清单
python3 synapse.py import-from-pi --default hyb
```

## 问题台账（issues.json）

发现 pi 使用问题时先记录、后优化，**未经下令不改 pi 配置**：

```bash
python3 synapse.py issue add --target hyb --model z-ai/glm-5.3 \
    --symptom "发图400" --cause "渠道拒收image" --plan "切换模型或disable-image"
python3 synapse.py issue note 1 --text "补充线索..."
python3 synapse.py issue status 1 doing   # open → doing → done / wontfix
python3 synapse.py issue list [--status open]
```

## 常见问题速查（判定 → 动作）

| 判定 | 含义 | 该做什么 |
|---|---|---|
| ✅ 正常 / 正常(截断) | 链路可用 | 无需处理 |
| ❌ 鉴权失败 | key 无效或欠费 | 换 key / 充值 |
| ❌ 配置不完整 | `config.json` 缺 `base_url`/`api_key`（或 `key_from_pi` 指向的 provider 不存在） | 补全该目标字段，或跑 `import-from-pi` 重新生成。**注意：这类站会显式报错，不会静默跳过** |
| 🐞 Synapse 内部错误 | **不是站的问题**，是本程序的 bug（异常分诊把网络故障和自身 bug 分开了） | 带着这一行提 issue；它不进连续失败计数，但整轮仍按异常返回 1 |
| ❌ 无可用渠道 | 模型名不对或该分组没这个模型 | 核对站内模型 ID（`[1M]` 后缀只是客户端标记，不会发出去） |
| ❌ 渠道不支持 thinking 参数 | 发 `thinking` 即 400（pi 里最常见的 `400 upstream_error`） | `fix --fix disable-reasoning --apply` |
| ❌ 请求被拒(400) | 渠道不认这个参数/字段 | `diagnose` 看细节 |
| ❌ 站侧无可用上游(auth_unavailable) | 渠道侧账号掉了/欠费 | **不是你的 key 错**，联系站方 |
| ⚠️ 被 Cloudflare/WAF 拦截 | 返回的是**拦截网页**（不是 API 错误），与 key 无关 | 先重试（多半是间歇性的）；反复拦就换出口/UA，或 `SYNAPSE_PROBE_TEXT` 换探测文本 |
| ⚠️ 被反测活拦截 | 探测文案命中站方关键词 | `SYNAPSE_PROBE_TEXT="讲个冷笑话" python3 synapse.py check` |
| ⚠️ 上游 5xx / 超时 / 限流 | 渠道不稳定 | 交给 `watch` 盯；连续多轮失败就临时停用该站 |
| ⚠️ 工具写成文本 | 模型没按协议发 tool_use，而是写成文本 | claude 系客户端多半能自纠，但说明渠道转译可疑 |
| ❌ 工具调用被渠道破坏 | tool_use 吐成坏 JSON/纯文本（如 cialo 的 `{"olls"read"...`） | 这种站只能纯聊天，**不能进 pi 的 agent 流程** |
| ✅ 工具调用正常(合规 tool_use 块) | 返回标准 tool_use | **只有这种站能进 pi 的 agent 流程** |
| ✅ 前缀缓存透传(cache_read>0) | 缓存真的透传 | 长会话每轮只付增量，省钱 |
| ⚠️ 前缀缓存不传(cache_read=0) | 缓存没透传 | pi 每轮全价重算，长上下文成本翻倍（issue#3） |
| 🖼 用户消息内嵌图 通过/被拒 | 粘贴图片进输入框的形态 | 被拒 → `fix --fix disable-image --apply` |
| 🖼 toolResult 注图 通过/被拒 | pi `read` 工具看图的形态 | 被拒 → 看图时直接粘贴进输入框，或换站 |

## 问题台账 workflow

```bash
python3 synapse.py issue add --target cialo --model glm-5.2 \
    --kind "agent工具调用" --symptom "带tools必超时" --cause "转译链损坏" --plan "排除出agent场景"
python3 synapse.py issue list --status open      # 只看未解决
python3 synapse.py issue note 5 --text "已复现"  # 加备注
python3 synapse.py issue status 5 done --text "已修复"
```

体检加 `--auto-issue` 时，以下情况会自动开单（24h 内同因去重，只追加“再次复现”备注）：
- `auth_failed` / `auth_unavailable` → 种类「配置/账号(key)」
- `no_channel`（模型名不对/该分组无此模型）→ 种类「模型名无渠道」
- `tool_call_broken`（agent 渠道损坏）
- 整站挂死（连 basic 都 `timeout` / `server_error`）
- 整站被 WAF 拦（按**站**开一条，不按模型刷）
- 目标配置不完整（缺 url/key）→ 种类「配置不完整」

**台账会自愈**：全量体检发现某条自动单已经恢复正常时，先记一笔“已恢复”；
**连续两轮**都正常则自动把状态改成 `fixed`。手工单（`auto: false`）和
「工具调用被渠道破坏」这类不会被自动关——前者要看人，后者是渠道痼疾。
定向抽查（`--target` / `--model`）不会参与自愈，也不能证明整体好了。

`check` 还会维护目标清单快照（`.targets_snapshot.json`）：若某站被删/禁用，会在下次全量体检时提醒“目标清单有变更未复查”，避免 pi 侧残留死站。

## 新增监控目标

编辑 `config.json`：

```jsonc
"targets": {
  "mynew": {
    "base_url": "https://example.com",   // 或 "key_from_pi": "某provider名"
    "api_key": "sk-xxx",
    "enabled": true,
    "models": ["glm-5.3"]
  }
}
```

## 开发与测试

纯 Python 标准库，无第三方依赖。

```bash
make help      # 列出所有开发目标
make test      # 138 项回归测试，不联网（带 ResourceWarning 严格模式）
make check     # 编译 + 测试，提交前跑这个
make smoke     # 用临时数据目录跑真实 CLI，不碰你的配置
make dist      # 先跑测试，通过才出 deb
```

测试钉住的是**判定层**——判错了会直接误导人去换 key 或改 pi 配置，所以
`classify()` 的优先级（WAF > 无渠道 > 鉴权 > …）、工具调用判据、台账去重、
自愈结单、`targets_of` 过滤与快照都有用例。

CLI 层也已可测：`main(argv, out, err)` 返回退出码、输出流可注入，所以
「`--json` 时 stdout 是否纯 JSON」「`fix` 不加 `--apply` 是否真的没写盘」
这类以前只能人肉看的事，现在是断言。退出码：`0` 正常 / `1` 有异常或配置缺失 /
`2` 用法错误。

CI（`.github/workflows/ci.yml`）在 py3.9–3.13 上跑测试，并检查打出来的 deb
里**不含任何数据/密钥文件**。

### 目录约定

- 源件：`synapse.py`、`man/`、`debian-doc/`、`packaging-src/`
- 生成物：`packaging/`（整棵树都由 `build-deb.sh` 生成）、`dist/`
- 用户数据：`~/.config/synapse/`（或 `$SYNAPSE_HOME`），永不入库、永不进包
