---
name: pulse
description: PULSE (项目脉搏) — engineering discipline audit for AI-assisted projects. Scans a directory of projects against surface + deep rules (git quality, test effectiveness, spec completeness, dependency health incl. npm audit, code size, secrets), generates a plain-language HTML report with trend comparison against the previous run, and can remediate common gaps. Run BEFORE starting work on any project, AFTER significant changes, or weekly with --ci.
---

# PULSE · 项目脉搏

给一个目录里的所有项目做"工程纪律体检"：表面检查回答"东西存不存在"，深度检查回答"它到底行不行"（提交质量、测试是否真校验结果、文档是否齐全、依赖有没有已知漏洞）。

报告说人话——写给不懂工程的读者也能看懂的体检单。

## 安装

```bash
git clone https://github.com/israelberne/pulse.git ~/.agents/skills/pulse
```

（ZCode 用户放到 `~/.zcode/skills/pulse`；也可以 clone 到任意位置后手动调用脚本。）

## 何时用

- 接手/开工一个项目之前（摸底）
- 完成一大轮改动之后（对照守则自查）
- 每周定时跑（报告自动对比上次，显示 改善/恶化/持平）
- 接手别人创建的项目

## 怎么跑

### 1. 生成报告

```bash
node <本技能目录>/tools/project-audit.cjs --root <项目所在的目录> --output <报告输出目录>
```

参数：
- `--root <dir>` — 要扫描的目录（默认：当前目录）
- `--output <dir>` — 报告输出目录（默认：`<root>/audits`）；每次运行落在 `<output>/<日期>/`，自动加载上一次结果做趋势对比
- `--rules core,security,docs,compliance,deep` — 启用哪些规则包（默认全部）
- `--fix git,agents,gitignore` — 预备修复项（需 `--confirm` 才执行）
- `--confirm` — 真正执行修复
- `--custom-rules <file.json>` — 加载自定义规则（见下）
- `--ci` — 有严重问题时退出码 1（供定时任务/自动化判断）

输出（每次都同时生成）：
- `index.html` — 可交互报告（严重级别筛选、按严重度/名称排序，纯内联 JS，file:// 直接打开）
- `audit-data.json` — 机器可读的结果

### 2. 把报告给用户看

用浏览器打开 `index.html`，同时在对话里总结要点。

### 3. 修复（用户确认后）

```bash
node <本技能目录>/tools/project-audit.cjs --root <目录> --fix git,agents,gitignore --confirm
```

可用的修复动作（全部安全、不破坏现有内容）：
- `git` — 初始化 git + 基线提交（没有 .gitignore 会先创建）
- `agents` — 从 `templates/AGENTS-skeleton.md` 创建协作规范
- `gitignore` — 创建标准 .gitignore

### 4. 定时运行

`--ci` 让退出码有意义：0 = 没有严重问题，1 = 至少一个项目有严重问题。
配合系统计划任务每周跑，日志示例：

```
MSYS_NO_PATHCONV=1 schtasks /Create /TN "weekly-pulse" /SC WEEKLY /D MON /ST 09:00 ^
  /TR "cmd /c node <技能目录>/tools/project-audit.cjs --root <项目目录> --ci > <日志路径> 2>&1" /F
```

## 规则包

### core — 表面（十条守则）
| ID | 检查 | 级别 |
|---|---|---|
| git | 版本控制已初始化 | 严重 |
| spec | 需求文档存在 | 警告 |
| tests | 自动化验证存在（类型感知：测试文件 / test 脚本 / 审计工具） | 警告 |
| design | 架构/设计文档存在 | 警告 |

### deep — 深度（读内容，不只看存在性）
| ID | 检查 | 级别 |
|---|---|---|
| git-quality | 提交消息质量、每次提交的文件数、最近活跃度 | 警告/建议 |
| spec-quality | 需求文档是否含四要素：范围、不做什么、验收标准、失败条款 | 警告/建议 |
| test-quality | 测试是否真的校验结果（而非只是跑一遍） | 警告/建议 |
| agents-living | 协作规范是否随时间更新（不是建完就忘） | 建议 |
| activity | 距最近提交天数、总提交数 | 建议 |
| secrets | 代码中的硬编码密钥；被 git 跟踪的敏感文件 | 严重 |
| dep-lockfile | 版本锁定 + 宽松版本号 + npm audit 已知漏洞（npm）/ requirements.txt 未钉死（python） | 警告/建议 |
| code-complexity | 最大文件行数、超 500 行文件数、待办标记密度 | 警告/建议 |

### security
| ID | 检查 | 级别 |
|---|---|---|
| secrets | （深度扫描，同上） | 严重 |
| gitignore | .gitignore 存在 | 严重 |

### docs
| ID | 检查 | 级别 |
|---|---|---|
| readme | README 存在 | 建议 |
| agents | AGENTS.md / CLAUDE.md 存在 | 警告 |
| retro | 复盘记录存在 | 建议 |

### compliance
| ID | 检查 | 级别 |
|---|---|---|
| license | LICENSE 存在 | 建议 |
| privacy | 公开部署的项目需有隐私说明 | 警告 |

## 自定义规则

`--custom-rules <file.json>` — JSON 数组，每条检查文件存在性：

```json
[
  {
    "id": "deploy-doc",
    "name": "部署说明",
    "severity": "info",
    "files": ["docs/deploy.md", "DEPLOY.md"],
    "mustExist": true,
    "impact": "换机器部署没有步骤可循。",
    "fix": "补一份部署说明"
  },
  {
    "id": "no-build-output",
    "name": "构建产物不入库",
    "severity": "warning",
    "files": ["dist/index.html"],
    "mustExist": false,
    "impact": "构建产物提交进仓库，和源码混在一起。",
    "fix": "把 dist/ 加进 .gitignore"
  }
]
```

`mustExist: true`（默认）：列出的文件必须都存在。`mustExist: false`：列出的文件一个都不能存在。

## 类型感知

项目类型自动识别（多包项目 / 网页应用 / 网站服务 / 工具库 / Python / 纯静态 / 未识别），检查随之适配：
- 测试检测按类型使用不同文件模式（如 Python 找 `test_*.py`，纯静态站找 `tools/audit*`）
- 依赖健康：npm 项目查版本锁定 + npm audit；Python 项目查 requirements.txt 钉死
- 规则带适用条件，不相干的检查直接跳过，不产生误报

## 报告用语规则（重要）

报告是给不懂工程的读者看的。必须遵守：

1. **平实语言** —— 不用行话、不造新词。说"测试会校验结果对错"，永远不说"断言"；说"版本锁定文件"，不说"lockfile"；说"出问题时查不到是哪次改动引入的"，不说"无法 bisect"。绕不开的技术概念（如 ^2.1.0）就地解释。
2. **全中文标签** —— 所有枚举值中文渲染：质量 好/一般/差/太浅（绝不出现 good/fair/poor/shallow）、项目类型 多包项目/网页应用/纯静态（绝不出现 monorepo/web-app）、表头"检查维度：核心、安全、文档、合规、深度"。新加规则必须遵守。
3. **不自称 AI** —— 不写"AI 分析""Claude 建议""由 XX 生成"
4. **不写过程叙事** —— 不写"我们发现""经过检查""可以看出"
5. **不留占位** —— 不写"TODO：待补充""未来版本""暂未实现"
6. **不暴露技术内部** —— 不写"系统提示词""思维链""token""LLM"
7. **事实直陈** —— "3 个项目没有 git"，而不是"我们注意到…"
8. **可执行** —— 每条发现都有影响（不修会怎样）和具体建议
9. **具体优于抽象** —— "抽查5个测试文件，1个会校验结果对错"，而不是"覆盖率 20%"
