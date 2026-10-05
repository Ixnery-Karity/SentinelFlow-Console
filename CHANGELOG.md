# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 与
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范。

## [1.1.0] - 2026-10-05

### Added — CTF 解题 Agent（`ctf/` 包）

- **解题 Agent 主体**（`ctf/solver.py`）：按「题型识别 → 知识库召回 → 多方案编排 → 执行 → 反思 → 沉淀」闭环运行；
  默认**离线可跑**，LLM 仅作可选兜底，失败静默降级。
- **离线工具箱**（`ctf/toolbox.py`，20 个工具）：Base64/Base32/Hex/URL/ROT13/摩斯/二进制/十进制ASCII/Unicode 解码、
  凯撒爆破、Atbash、栅栏爆破、倒序、单字节 XOR 爆破、哈希类型识别、弱口令字典比对、文件头识别、flag 扫描等。
- **自动套娃解码**（`auto_decode_chain`）：广度优先组合编码工具，支持**同一工具嵌套**（如双重 Base64），
  命中链路可追溯。
- **本地知识库**（`ctf/knowledge.py`）：SQLite + **FTS5 全文检索**（中文用 trigram 分词）。
  - 知识卡按 `fingerprint` **幂等写入**，重复出现只累加置信度，不产生重复行；
  - `reinforce()` 按实战成败动态调整 `confidence`，越用越准。
- **自主学习闭环**：每次解题（无论成败）自动提炼知识卡 —— 成功记 `recipe`（工具链）与 `pattern`（特征→首选工具），
  失败记 `pitfall`（避免重复踩坑）；**下一次同题型优先召回高分经验，并把它排到方案队首**。
- **可信度机制**：`flag_confidence()` 区分真实 flag 与编码误报（如 ROT13 产出的 `vbqw{squiqh}` 乱码），
  低可信结果标记 `needs_review` 供人工复核。
- **命令行**：`python -m ctf solve|demo|kb|tools|selftest`。

### Added — 真实执行层（`realexec.py`）

- **三级降级**：真实外部工具（nmap/dirb/sqlmap）→ 内置脚本 → 确定性模拟，任何环境都能跑通。
- **内置真实脚本**（`scripts/`，纯 Python 零依赖）：`port_probe.py`（TCP 连接探测）、
  `http_fingerprint.py`（HTTP 指纹）、`dir_probe.py`（低风险路径探测）—— 均**真连真跑**。
- **安全边界**：默认 `enabled=False` 不执行任何命令；目标必须落在私网/回环白名单；需显式授权标记；
  强制超时、输出截断、速率限制；**只走参数数组、不使用 shell=True**。
- **可审计**：每次执行（含成功路径）写入 JSONL 审计日志。
- **工作流集成**：`workflow.py` 侦察节点支持 `real_exec` 开关，节点数保持 10 个，向后兼容。

### Changed

- `workflow.py`：侦察节点改为「模拟 / 真实执行」双模式，`artifacts` 新增 `recon_exec` 字段。
- `.gitignore`：排除运行时产物（`data/`、`*.db`、`*.jsonl` 等）。

### Fixed

- 指纹归一化正则误写（`\\s+` → `\s+`）导致大小写/空格不同的同一知识点产生重复卡片。
- 自动解码禁止重复工具，导致双重 Base64 等嵌套编码解不出。
- 候选计划数上限过低（8），使哈希类题目来不及触发弱口令比对。
- **真实执行成功路径漏写审计日志** —— 违反可审计性原则，已重构为「所有分支统一落盘」。

### Tests

- 新增 `tests/test_ctf.py`（36 项）与 `tests/test_realexec.py`（31 项），**全量 67 项通过**。

## [1.0.0] - 2026-08-04

### Added

- 8 个安全能力脚本（代码审计与修复、PAE、SOP 检索、JVM 内存马查杀、PatchDiff、二进制语义恢复、提示词注入防护）。
- 10 节点工作流编排（`workflow.py`）与 Flask 控制台（`app.py`，3 个 API）。
- 默认零模型调用 / 零网络扫描 / 零命令执行的安全姿态；命令执行网关永久封禁。
- pytest 测试与设计系统文档。
