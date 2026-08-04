# MyAgentForSecurityCheckingAndFixing

一个面向授权内网靶场的安全检查工作流控制台。项目把原目录中的 8 个实验脚本统一成一个可运行的、离线优先的 agent：

范围校验 → 规划 → 侦察模拟 → 代码审计 → JVM 内存排查 → PatchDiff → 二进制分析 → SOP 检索 → 提示词注入防护 → 报告

## 安全边界

- 默认不调用模型、不发起网络扫描、不执行系统命令。
- 所有侦察工具返回明确的 simulation 结果，适合先验证编排和前端。
- 外部日志被视为不可信输入；检测到提示词注入后工作流会标记为 blocked。
- 模型输出永远不会直接进入 shell。若要接入 OpenAI-compatible 服务，需要显式设置 AI_ENABLED=true，并仍由业务代码完成校验和审批。

## 快速启动

~~~powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app.py
~~~

打开 http://127.0.0.1:5000。页面提供默认样例，点击“开始安全检查”即可看到完整工作流、风险指标和审计事件。

## API

- GET /api/health：健康检查
- POST /api/workflow/run：运行端到端工作流，JSON 字段可传 target、objective、code、diff、logs、pseudocode、question
- POST /api/audit：只运行代码审计

## 8 个兼容入口

原始文件名保留，均可直接运行并输出 JSON。它们现在共享 core.py，不会重复初始化客户端或依赖本地向量模型：

~~~powershell
python "1-代码审计和修复引擎.py"
python "2-PAE.py"
python "3-sop.py"
python "4-MCP工具查杀引擎.py"
python "5-自动化patchdiff漏洞分析引擎引擎.py"
python "6-PAE自动渗透.py"
python "7-AI赋能进行二进制分析插件.py"
python "8-间接提示词注入导致服务器RCE漏洞.py"
~~~

## 目录

- core.py：安全的离线分析器和工具适配器
- workflow.py：上下游编排与统一报告
- app.py：Flask API 与静态页面入口
- static/：响应式运维控制台
- design-system/security-workflow-console/MASTER.md：按 UI/UX Pro Max 生成的设计系统
- tests/：核心、API 和兼容入口测试
