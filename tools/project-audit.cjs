#!/usr/bin/env node
/* project-audit.cjs v2.1 — 深度工程纪律审计引擎
 *
 * v1 → v2 升级：
 *   1. 类型感知：按 package.json/scripts/文件后缀 自动适配检查逻辑（消除误报）
 *   2. 深度检查：读 git 提交质量、读测试内容质量、读 spec 内容完整性
 *   3. 时间维度：自动对比上次审计，标注趋势（↑恶化 ↓改善 →持平 ★新增）
 *   4. 依赖健康：版本锁定 + 宽松版本号 + npm audit 已知漏洞（npm）/ 版本钉死（pip）
 *
 * v2.1：
 *   5. 代码体量：最大文件行数、超500行文件数、待办标记密度
 *   6. 报告交互：按严重级别筛选、按严重度/名称排序（纯内联 JS，file:// 可用）
 *   7. --custom-rules <file.json> 自定义规则（检查某些文件必须/不能存在）
 *   8. --ci 门禁：有严重问题返回退出码 1，供定时任务判断
 *
 * 用法：node project-audit.cjs --root <项目目录> [--output dir] [--fix items] [--confirm] [--custom-rules f.json] [--ci]
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/* ---------- 参数 ---------- */
const args = process.argv.slice(2);
const get = (flag, def) => { const i = args.indexOf(flag); return i > -1 ? args[i + 1] : def; };
const ROOT = get('--root', process.cwd());
const OUT_BASE = get('--output', path.join(ROOT, 'audits'));
const RULE_PACKS = (get('--rules', 'core,security,docs,compliance,deep')).split(',');
const FIX_ITEMS = args.includes('--fix') ? (get('--fix', '') || '').split(',').filter(Boolean) : [];
const CONFIRM = args.includes('--confirm');
/* 用本地日期做报告目录名（toISOString 是 UTC，东八区早上跑会差一天） */
const TODAY = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 10);
const NULL_DEV = process.platform === 'win32' ? '2>nul' : '2>/dev/null';

if (!fs.existsSync(ROOT)) {
  console.error(`--root 指向的目录不存在：${ROOT}`);
  process.exit(2);
}

/* ---------- 工具函数 ---------- */
function sh(cmd, dir, timeout = 5000) {
  try {
    return execSync(cmd, { encoding: 'utf8', cwd: dir, timeout }).trim();
  } catch (e) { return ''; }
}

function readJSON(fp) { try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch (e) { return null; } }

/* npm audit 发现漏洞时退出码为 1，结果仍在标准输出里——这条命令要拿到 stdout 而不是当失败丢弃 */
function shKeepOutput(cmd, dir, timeout = 15000) {
  try {
    return execSync(cmd, { encoding: 'utf8', cwd: dir, timeout }).trim();
  } catch (e) {
    return (e.stdout || '').trim();
  }
}

/* ---------- 项目类型检测 ---------- */
function detectProjectType(dir) {
  const pkg = readJSON(path.join(dir, 'package.json'));
  const hasPy = fs.existsSync(path.join(dir, 'requirements.txt')) || fs.existsSync(path.join(dir, 'pyproject.toml'));
  const hasStatic = fs.existsSync(path.join(dir, 'index.html')) && !pkg;
  const hasVite = pkg && (pkg.devDependencies?.vite || pkg.dependencies?.vite);
  const hasWorker = fs.existsSync(path.join(dir, 'wrangler.toml')) || fs.existsSync(path.join(dir, 'worker'));

  if (pkg?.workspaces || fs.existsSync(path.join(dir, 'pnpm-workspace.yaml'))) return 'monorepo';
  if (hasVite) return 'web-app';
  if (pkg?.scripts?.start || pkg?.main?.includes('server')) return 'node-server';
  if (pkg) return 'node-lib';
  if (hasPy) return 'python';
  if (fs.existsSync(path.join(dir, 'go.mod'))) return 'go';
  if (fs.existsSync(path.join(dir, 'Cargo.toml'))) return 'rust';
  if (hasStatic) return 'static';
  return 'unknown';
}

/* ---------- 测试检测（类型感知，消除误报） ---------- */
const TEST_PATTERNS = {
  'web-app': ['*.test.ts', '*.test.tsx', '*.test.js', '*.spec.ts', 'tests/*.test.*', 'src/**/*.test.*', 'e2e/*.*'],
  'node-server': ['*.test.ts', '*.test.js', 'test/*.*', 'tests/*.*'],
  'node-lib': ['*.test.ts', '*.test.js', 'test/*.*', '__tests__/*.*'],
  'monorepo': ['packages/**/*.test.ts', 'apps/**/*.test.*', 'packages/**/tests/*.*'],
  'python': ['test_*.py', '*_test.py', 'tests/test_*.py'],
  'static': ['tools/smoke*', 'tools/audit*', 'tools/check*', 'tools/verify*', 'tools/test*'],
  'unknown': ['*.test.*', '*smoke*', '*check*', '*audit*'],
};

function detectTests(dir, type) {
  const patterns = TEST_PATTERNS[type] || TEST_PATTERNS.unknown;
  const results = { count: 0, hasRealTests: false, testFiles: [], hasTestScript: false, hasSmokeScript: false, hasAuditTool: false };

  // 方法1：package.json scripts 里有 test 或相关命令
  const pkg = readJSON(path.join(dir, 'package.json'));
  if (pkg?.scripts) {
    const scripts = Object.keys(pkg.scripts);
    results.hasTestScript = scripts.some(s => /test|vitest|jest|mocha/.test(s));
    results.hasSmokeScript = scripts.some(s => /smoke|audit|verify|check/.test(s));
  }

  // 方法2：按类型适配的文件模式搜索
  for (const pat of patterns) {
    const base = pat.split('/').pop();
    const isGlob = base.includes('*');
    if (isGlob) {
      const ext = base.replace(/\*/g, '');
      const prefix = base.split('*')[0];
      const walk = (d, depth) => {
        if (depth > 4 || results.testFiles.length > 20) return;
        try {
          for (const f of fs.readdirSync(d, { withFileTypes: true })) {
            if (f.name.startsWith('.') || f.name === 'node_modules') continue;
            const fp = path.join(d, f.name);
            if (f.isDirectory()) walk(fp, depth + 1);
            else if (f.name.startsWith(prefix === '' ? 'test' : prefix) && f.name.includes(ext.replace('.', ''))) {
              results.testFiles.push(fp);
            }
          }
        } catch (e) {}
      };
      walk(dir, 0);
    }
  }

  // 方法3：工具目录下的验证脚本（对 static/unknown 类型特别重要）
  const toolDirs = ['tools', 'scripts', 'edgeqa-run'];
  for (const td of toolDirs) {
    const tdir = path.join(dir, td);
    if (fs.existsSync(tdir)) {
      try {
        for (const f of fs.readdirSync(tdir)) {
          if (/smoke|audit|check|verify|test|geometry|console/i.test(f)) {
            results.testFiles.push(path.join(tdir, f));
            results.hasAuditTool = true;
          }
        }
      } catch (e) {}
    }
  }

  // 方法4：playwright/jest/vitest 配置文件
  const testConfigs = ['playwright.config.ts', 'vitest.config.ts', 'jest.config.js', 'jest.config.ts', 'pytest.ini', 'conftest.py'];
  results.hasTestConfig = testConfigs.some(c => fs.existsSync(path.join(dir, c)));

  results.count = [...new Set(results.testFiles)].length;
  results.hasRealTests = results.count > 0 || results.hasTestScript || results.hasSmokeScript || results.hasAuditTool || results.hasTestConfig;

  // 深度检查：测试会不会校验结果对不对（而不是只跑一遍）
  if (results.count > 0) {
    let assertCount = 0;
    for (const tf of results.testFiles.slice(0, 5)) {
      try {
        const content = fs.readFileSync(tf, 'utf8');
        if (/expect\(|assert |should\.|toBe\(|toEqual\(|toMatch\(|\.ok\b|PASS.*FAIL|console\.error/.test(content)) {
          assertCount++;
        }
      } catch (e) {}
    }
    results.hasAssertions = assertCount > 0;
    results.assertionRatio = results.count > 0 ? assertCount / Math.min(results.count, 5) : 0;
  }

  return results;
}

/* ---------- Git 提交质量分析 ---------- */
function analyzeGitQuality(dir) {
  if (!fs.existsSync(path.join(dir, '.git'))) return null;

  const log = sh('git log --oneline -20', dir);
  if (!log) return null;

  const commits = log.split('\n').filter(Boolean);
  const messages = commits.map(c => c.replace(/^[a-f0-9]+\s+/, ''));
  const avgLen = messages.reduce((a, m) => a + m.length, 0) / messages.length;
  const shortMsgs = messages.filter(m => m.length < 10).length;
  const vagueMsgs = messages.filter(m => /^(fix|update|change|test|wip|tmp|修复|更新|修改|调整|完善|调试|临时|杂项)[.。:：]?\s*$/i.test(m.trim())).length;

  // 原子性：每次提交改了多少文件
  let filesPerCommit = [];
  for (let i = 0; i < Math.min(commits.length, 10); i++) {
    const hash = commits[i].split(' ')[0];
    const stat = sh(`git show --stat --format="" ${hash}`, dir);
    const fileCount = stat ? stat.split('\n').filter(l => l.includes('|')).length : 0;
    filesPerCommit.push(fileCount);
  }
  const avgFiles = filesPerCommit.reduce((a, b) => a + b, 0) / (filesPerCommit.length || 1);

  // 活跃度：最近提交距今多少天
  const lastDate = sh('git log -1 --format=%ci', dir);
  const daysSinceLast = lastDate ? Math.floor((Date.now() - new Date(lastDate)) / 86400000) : 999;

  // AGENTS.md 更新频率（如果存在且有 git）
  let agentsUpdates = 0;
  if (fs.existsSync(path.join(dir, 'AGENTS.md'))) {
    agentsUpdates = sh('git log --oneline -- AGENTS.md', dir).split('\n').filter(Boolean).length;
  }

  const vagueRatio = vagueMsgs / commits.length;
  return {
    totalCommits: parseInt(sh('git rev-list --count HEAD', dir)) || commits.length,
    avgMsgLen: Math.round(avgLen),
    shortMsgRatio: shortMsgs / commits.length,
    vagueMsgRatio: vagueRatio,
    avgFilesPerCommit: Math.round(avgFiles * 10) / 10,
    daysSinceLastCommit: daysSinceLast,
    agentsUpdateCount: agentsUpdates,
    quality: avgLen >= 20 && vagueRatio < 0.3 && avgFiles <= 8 ? 'good' :
              avgLen >= 10 && vagueRatio < 0.5 ? 'fair' : 'poor',
  };
}

/* ---------- 依赖健康分析 ---------- */
function analyzeDependencies(dir, type) {
  const pkgPath = path.join(dir, 'package.json');
  const pkg = readJSON(pkgPath);
  if (!pkg && type !== 'python') return null;

  // python 项目：检查 requirements.txt 版本钉死
  if (!pkg && type === 'python') {
    const reqPath = path.join(dir, 'requirements.txt');
    if (!fs.existsSync(reqPath)) return null;
    const lines = fs.readFileSync(reqPath, 'utf8').split('\n')
      .map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    const unpinned = lines.filter(l => !/[=><]/.test(l));
    return {
      manager: 'pip',
      totalDeps: lines.length,
      unpinnedCount: unpinned.length,
      unpinnedDeps: unpinned.slice(0, 3),
      health: unpinned.length > lines.length * 0.3 ? 'poor' : unpinned.length > 0 ? 'fair' : 'good',
    };
  }

  const hasLockfile = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'].some(l => fs.existsSync(path.join(dir, l)));

  const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const depEntries = Object.entries(allDeps);
  const wildcardDeps = depEntries.filter(([name, ver]) => ver === '*' || ver === 'latest' || ver === 'x');
  const careDeps = depEntries.filter(([name, ver]) => ver.startsWith('^') || ver.startsWith('~'));

  // 检查高危依赖
  const riskyDeps = depEntries.filter(([name]) =>
    /request|left-pad|event-stream|colors/.test(name)
  );

  // 已知漏洞检查（npm audit 只认 package-lock.json；pnpm/yarn 锁文件的项目跳过）
  let vuln = null;
  if (fs.existsSync(path.join(dir, 'package-lock.json'))) {
    const out = shKeepOutput(`npm audit --json ${NULL_DEV}`, dir, 15000);
    if (out) {
      try {
        const audit = JSON.parse(out);
        const meta = audit.metadata?.vulnerabilities;
        if (meta) vuln = { high: meta.high || 0, critical: meta.critical || 0, total: meta.total || 0 };
      } catch (e) {}
    }
  }

  return {
    manager: 'npm',
    totalDeps: depEntries.length,
    hasLockfile,
    wildcardCount: wildcardDeps.length,
    wildcardDeps: wildcardDeps.map(([n]) => n),
    careDepsRatio: depEntries.length ? careDeps.length / depEntries.length : 0,
    riskyDeps: riskyDeps.map(([n]) => n),
    vuln,
    health: (vuln && vuln.critical > 0) || !hasLockfile ? 'poor' :
            wildcardDeps.length > 3 || (vuln && vuln.high > 0) ? 'poor' :
            wildcardDeps.length > 0 ? 'fair' : 'good',
  };
}

/* ---------- 代码体量与待办标记分析 ---------- */
function analyzeComplexity(dir) {
  const codeExts = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.jsx'];
  const skipDirs = ['node_modules', '.git', '__pycache__', '.cache', 'coverage', '.next', 'release', 'out', 'bundle', 'vendor'];
  const isSkipped = n => skipDirs.includes(n) || n.startsWith('dist') || n.startsWith('build');
  let largestFile = '';
  let largestLines = 0;
  let bigFileCount = 0;   // 超过 500 行的文件数
  let todoCount = 0;
  let scannedFiles = 0;

  const scanDir = (d, depth) => {
    if (depth > 4 || scannedFiles > 400) return;
    try {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        if (isSkipped(entry.name) || entry.name.startsWith('.')) continue;
        const fp = path.join(d, entry.name);
        if (entry.isDirectory()) { scanDir(fp, depth + 1); }
        else if (codeExts.includes(path.extname(entry.name))) {
          scannedFiles++;
          try {
            const content = fs.readFileSync(fp, 'utf8');
            const lines = content.split('\n').length;
            if (lines > largestLines) { largestLines = lines; largestFile = path.relative(dir, fp); }
            if (lines > 500) bigFileCount++;
            const todos = content.match(/TODO|FIXME|HACK/g);
            if (todos) todoCount += todos.length;
          } catch (e) {}
        }
      }
    } catch (e) {}
  };
  scanDir(dir, 0);

  return { largestFile, largestLines, bigFileCount, todoCount, scannedFiles,
           health: largestLines > 1500 || bigFileCount > 5 ? 'poor' :
                   largestLines > 800 || bigFileCount > 2 || todoCount > 20 ? 'fair' : 'good' };
}

/* ---------- Spec 内容质量分析 ---------- */
function analyzeSpecQuality(dir) {
  const specDirs = ['.zcode/plans', 'docs/specs', 'docs/superpowers/specs'];
  let specContent = '';
  let specFile = '';

  for (const sd of specDirs) {
    const sdir = path.join(dir, sd);
    if (fs.existsSync(sdir)) {
      try {
        const files = fs.readdirSync(sdir).filter(f => f.endsWith('.md'));
        if (files.length) {
          // 读最新的
          specFile = path.join(sdir, files.sort().pop());
          specContent = fs.readFileSync(specFile, 'utf8');
          break;
        }
      } catch (e) {}
    }
  }

  if (!specContent) {
    // 也检查根目录的 spec 文件
    for (const f of ['spec.md', 'SPEC.md', 'docs/spec.md']) {
      const fp = path.join(dir, f);
      if (fs.existsSync(fp)) {
        specContent = fs.readFileSync(fp, 'utf8');
        specFile = fp;
        break;
      }
    }
  }

  if (!specContent) return { exists: false };

  // 检查关键要素
  const hasNotDo = /不做什么|明确不|out of scope|非目标|边界/.test(specContent);
  const hasFailure = /失败|失败条款|失败条件|abort|归档/.test(specContent);
  const hasAcceptance = /验收|acceptance|判定|通过标准/.test(specContent);
  const hasScope = /范围|scope|做什么/.test(specContent);

  const qualityScore = [hasNotDo, hasFailure, hasAcceptance, hasScope].filter(Boolean).length;

  return {
    exists: true,
    file: path.basename(specFile),
    hasNotDo, hasFailure, hasAcceptance, hasScope,
    quality: qualityScore >= 3 ? 'good' : qualityScore >= 2 ? 'fair' : 'shallow',
  };
}

/* ---------- 密钥安全深度扫描 ---------- */
function deepSecretScan(dir) {
  const issues = [];

  // 检查当前代码中的硬编码密钥
  const secretPattern = /(?:sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9]{20,})/;
  const codeExts = ['.ts', '.tsx', '.js', '.jsx', '.py', '.mjs', '.sh'];
  const skipDirs = ['node_modules', '.git', 'dist', 'build', '__pycache__', '.cache'];

  const scanDir = (d, depth) => {
    if (depth > 4) return;
    try {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        if (skipDirs.includes(entry.name) || entry.name.startsWith('.')) continue;
        const fp = path.join(d, entry.name);
        if (entry.isDirectory()) { scanDir(fp, depth + 1); }
        else if (codeExts.includes(path.extname(entry.name))) {
          try {
            const content = fs.readFileSync(fp, 'utf8');
            const match = content.match(secretPattern);
            if (match && !content.includes('process.env') && !content.includes('.env.local') && !fp.includes('.d.ts') && !fp.includes('example')) {
              issues.push({ file: path.relative(dir, fp), snippet: match[0].slice(0, 20) + '...' });
            }
          } catch (e) {}
        }
      }
    } catch (e) {}
  };
  scanDir(dir, 0);

  // 检查 .env 文件是否被 git 跟踪（如果有 git）——在 JS 里过滤，不依赖 grep
  if (fs.existsSync(path.join(dir, '.git'))) {
    const envTracked = sh('git ls-files', dir).split('\n')
      .find(f => /^\.env(\.|$)/.test(f) && !f.includes('.env.example'));
    if (envTracked) {
      issues.push({ file: envTracked, snippet: '敏感文件被 git 跟踪' });
    }
  }

  return issues;
}

/* ---------- 上次审计结果加载（时间维度） ---------- */
function loadPreviousAudit(outputBase) {
  try {
    const auditDirs = fs.readdirSync(outputBase)
      .filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d))
      .sort()
      .filter(d => d < TODAY); // 今天之前的
    if (!auditDirs.length) return null;
    const prevDir = auditDirs[auditDirs.length - 1];
    const prevPath = path.join(outputBase, prevDir, 'audit-data.json');
    if (fs.existsSync(prevPath)) {
      return { date: prevDir, data: readJSON(prevPath) };
    }
  } catch (e) {}
  return null;
}

/* ---------- 比较两次审计（趋势） ---------- */
function computeTrend(current, previous) {
  if (!previous) return null;
  const prevMap = {};
  previous.forEach(p => {
    prevMap[p.name] = new Set(p.findings.map(f => f.id));
  });

  return current.map(proj => {
    const prev = prevMap[proj.name];
    if (!prev) return { ...proj, trend: 'new' };

    const currentIds = new Set(proj.findings.map(f => f.id));
    const newIssues = proj.findings.filter(f => !prev.has(f.id));
    const resolvedIssues = [...prev].filter(id => !currentIds.has(id));
    const persistentIssues = proj.findings.filter(f => prev.has(f.id));

    let trend = 'stable';
    if (newIssues.length > resolvedIssues.length) trend = 'worse';
    else if (resolvedIssues.length > newIssues.length) trend = 'better';
    if (newIssues.length === 0 && resolvedIssues.length === 0 && persistentIssues.length === 0) trend = 'clean';
    if (newIssues.length === 0 && resolvedIssues.length === 0 && persistentIssues.length > 0) trend = 'stable';

    return {
      ...proj,
      trend,
      newIssueIds: newIssues.map(f => f.id),
      resolvedIssueIds: resolvedIssues,
      newCount: newIssues.length,
      resolvedCount: resolvedIssues.length,
    };
  });
}

/* ---------- 项目扫描主逻辑 ---------- */
function findProjects(root) {
  const SKIP = ['node_modules', '.git', 'audits', '__pycache__', 'dist', 'build', '.zcode', '.claude', 'repos'];
  const MARKER_FILES = ['package.json', 'requirements.txt', 'pyproject.toml', 'setup.py', 'go.mod', 'Cargo.toml',
    'pom.xml', 'build.gradle', 'composer.json', 'Gemfile', 'CMakeLists.txt', 'Makefile', 'deno.json', 'index.html'];
  const MARKER_DIRS = ['src', 'js', 'tools', 'apps', 'packages', 'app', 'web', 'server', 'lib'];
  const CODE_EXTS = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.go', '.rs', '.java', '.rb', '.php', '.vue', '.svelte'];
  const hasCode = d => { try { return fs.readdirSync(d).some(f => CODE_EXTS.includes(path.extname(f))); } catch (e) { return false; } };
  // 往下看两层：不少项目根目录只有文档，代码在 app/src 这类子目录里
  const hasCodeDeep = d => {
    try {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (e.isDirectory()) { if (hasCode(path.join(d, e.name))) return true; }
        else if (CODE_EXTS.includes(path.extname(e.name))) return true;
      }
    } catch (e2) {}
    return false;
  };
  return fs.readdirSync(root, { withFileTypes: true })
    .filter(d => d.isDirectory() && !SKIP.includes(d.name) && !d.name.startsWith('.'))
    .map(d => d.name)
    .filter(name => {
      const dir = path.join(root, name);
      if (MARKER_FILES.some(f => fs.existsSync(path.join(dir, f)))) return true;
      // 只有目录标志时，还得里面有代码文件，避免把普通文件夹当项目
      return MARKER_DIRS.some(md => {
        const sub = path.join(dir, md);
        return fs.existsSync(sub) && (hasCodeDeep(dir) || hasCodeDeep(sub));
      });
    })
    .sort();
}

function scanProject(root, name) {
  const dir = path.join(root, name);
  const p = {
    name, dir,
    type: detectProjectType(dir),
    hasFile: f => fs.existsSync(path.join(dir, f)),
  };

  // 测试（类型感知 + 深度）
  p.tests = detectTests(dir, p.type);

  // Git 质量
  p.gitQuality = analyzeGitQuality(dir);

  // 依赖健康（按项目类型）
  p.deps = analyzeDependencies(dir, p.type);

  // 代码体量与待办标记
  p.complexity = analyzeComplexity(dir);

  // Spec 质量
  p.specQuality = analyzeSpecQuality(dir);

  // 密钥深度扫描
  p.secretIssues = deepSecretScan(dir);

  // 公开检测
  p.isPublic = p.hasFile('CNAME') || p.hasFile('vercel.json') || p.hasFile('netlify.toml') || p.hasFile('docker-compose.yml');

  return p;
}

/* ---------- 规则引擎（v2：表面 + 深度两级，类型感知） ---------- */
function depSeverity(p) {
  if (!p.deps) return 'info';
  return p.deps.health === 'poor' ? 'warning' : 'info';
}
function depDetail(p) {
  if (!p.deps) return '';
  if (p.deps.manager === 'pip') {
    return `Python 依赖 ${p.deps.totalDeps} 个 · 未钉死版本的 ${p.deps.unpinnedCount} 个${p.deps.unpinnedCount ? `（如 ${p.deps.unpinnedDeps.join('、')}）` : ''}`;
  }
  const v = p.deps.vuln;
  return `依赖 ${p.deps.totalDeps} 个 · ${p.deps.hasLockfile ? '有版本锁定文件' : '无版本锁定文件'} · 宽松版本号 ${p.deps.wildcardCount} 个` +
         (v ? ` · 已知漏洞 ${v.total} 个（严重 ${v.critical} 个、高危 ${v.high} 个）` : '');
}
const depImpact = p => p.deps?.manager === 'pip'
  ? '依赖不钉死版本，换台机器或过几个月重装，装到的版本可能完全不同，程序直接跑不起来。'
  : '没有版本锁定文件，每次安装可能装到不同版本，今天能跑明天就坏；已知漏洞说明正带着安全问题在运行。';
const depFix = p => p.deps?.manager === 'pip'
  ? '在 requirements.txt 里把每个依赖写成形如 requests==2.31.0 的精确版本（命令 pip freeze > requirements.txt 可一次全钉死）'
  : '生成版本锁定文件（在项目里执行一次 npm install 或 pnpm install 即可）；有已知漏洞的，按 npm audit 的提示升级对应依赖';

/* 报告用词统一为中文 */
const TYPE_LABELS = { monorepo: '多包项目', 'web-app': '网页应用', 'node-server': '网站服务', 'node-lib': '工具库', python: 'Python', go: 'Go 项目', rust: 'Rust 项目', static: '纯静态', unknown: '未识别' };
const QUALITY_LABELS = { good: '好', fair: '一般', poor: '差', shallow: '太浅' };
const PACK_LABELS = { core: '核心', security: '安全', docs: '文档', compliance: '合规', deep: '深度', custom: '自定义' };

const RULES = [
  // === core：十条守则映射 ===
  { id: 'git', pack: 'core', level: 'surface', severity: 'critical', name: '版本控制',
    check: p => !!p.gitQuality,
    impact: '无法回滚错误改动，无法查看修改历史，多轮迭代中无法定位引入问题的提交。',
    fix: 'git init + 首次全量 commit' },
  { id: 'git-quality', pack: 'deep', level: 'deep', severity: p => p.gitQuality?.quality === 'poor' ? 'warning' : 'info',
    name: '提交质量',
    check: p => !p.gitQuality || p.gitQuality.quality === 'good',
    detail: p => p.gitQuality ? `提交消息均长${p.gitQuality.avgMsgLen}字 · 模糊消息${Math.round(p.gitQuality.vagueMsgRatio*100)}% · 平均每次提交${p.gitQuality.avgFilesPerCommit}个文件 · 质量${QUALITY_LABELS[p.gitQuality.quality] || p.gitQuality.quality}` : '',
    impact: '提交消息含糊，出问题时查不到是哪次改动引入的；一次提交混入几十个文件的改动，想回退某一处时退不干净。',
    fix: '每提交做一件事；消息格式：动词+对象+原因（如 "fix: 时区转换在午夜后偏移一天，改用本地时区计算日界线"）' },
  { id: 'spec', pack: 'core', level: 'surface', severity: 'warning', name: '需求文档',
    check: p => p.specQuality?.exists,
    impact: '需求未对齐即动工，导致推倒重来或后期范围失控。',
    fix: '创建一页 spec' },
  { id: 'spec-quality', pack: 'deep', level: 'deep', severity: p => p.specQuality?.quality === 'shallow' ? 'warning' : 'info',
    name: 'Spec 完整性',
    check: p => !p.specQuality?.exists || p.specQuality.quality !== 'shallow',
    detail: p => p.specQuality?.exists ? `包含：${p.specQuality.hasScope?'范围':'—'} / ${p.specQuality.hasNotDo?'不做什么':'—'} / ${p.specQuality.hasAcceptance?'验收':'—'} / ${p.specQuality.hasFailure?'失败条款':'—'} → ${QUALITY_LABELS[p.specQuality.quality] || p.specQuality.quality}` : '没有需求文档',
    impact: '缺少"明确不做什么"导致范围蔓延；缺少失败条款导致项目无限拖延不敢终止。',
    fix: 'spec 中补充四要素：做什么、不做什么、验收标准、失败条款' },
  { id: 'tests', pack: 'core', level: 'surface', severity: 'warning', name: '自动化验证',
    check: p => p.tests.hasRealTests,
    detail: p => {
      const parts = [];
      if (p.tests.count) parts.push(`${p.tests.count}个测试文件`);
      if (p.tests.hasTestScript) parts.push('test命令');
      if (p.tests.hasAuditTool) parts.push('审计工具');
      if (p.tests.hasTestConfig) parts.push('测试配置');
      return parts.join(' + ') || '未检测到';
    },
    impact: '改动后没有自动检查，原有功能被改坏也不会被发现；测试全绿不等于真机能用。',
    fix: '至少添加关键路径的自动化验证' },
  { id: 'test-quality', pack: 'deep', level: 'deep', severity: p => p.tests.count > 0 && !p.tests.hasAssertions ? 'warning' : 'info',
    name: '测试有效性',
    check: p => p.tests.count === 0 || p.tests.hasAssertions,
    detail: p => {
      if (!p.tests.count) return '';
      const sampled = Math.min(p.tests.count, 5);
      const hit = Math.round((p.tests.assertionRatio||0) * sampled);
      return `抽查${sampled}个测试文件，${hit}个会校验结果对错${hit === 0 ? '——只是跑了一遍，没核对（占位测试）' : ''}`;
    },
    impact: '有测试文件但从不检查结果对错 = 假测试，全绿也不代表功能正常，给人虚假的安全感。',
    fix: '让每个测试检查实际结果和预期是否一致，而不是只执行一遍不核对' },
  { id: 'design', pack: 'core', level: 'surface', severity: 'warning', name: '设计文档',
    check: p => p.hasFile('AGENTS.md') || p.hasFile('CLAUDE.md') || p.hasFile('agent.md') || p.hasFile('docs/architecture.md') || p.hasFile('01-总体架构与决策.md'),
    impact: '架构决策无记录，后续维护者不知道为什么这样设计。',
    fix: '创建 AGENTS.md 或架构决策记录' },
  { id: 'agents-living', pack: 'deep', level: 'deep', severity: 'info',
    name: '规范活性',
    check: p => !p.gitQuality || p.gitQuality.agentsUpdateCount >= 2,
    detail: p => p.gitQuality ? `AGENTS.md 更新次数：${p.gitQuality.agentsUpdateCount}` : '',
    impact: 'AGENTS.md 创建后从不更新 = 规则没有随教训增长，形同虚设。',
    fix: '每次返工后更新 AGENTS.md 中的规则' },
  { id: 'activity', pack: 'deep', level: 'deep', severity: p => p.gitQuality && p.gitQuality.daysSinceLastCommit > 30 ? 'info' : 'info',
    name: '维护活跃度',
    check: () => true, // 信息类，不判过/不过
    detail: p => p.gitQuality ? `最近提交：${p.gitQuality.daysSinceLastCommit}天前 · 总提交：${p.gitQuality.totalCommits}` : '无git',
    impact: '',
    fix: '' },
  // === security ===
  { id: 'secrets', pack: 'security', level: 'deep', severity: 'critical', name: '密钥泄露',
    check: p => p.secretIssues.length === 0,
    detail: p => p.secretIssues.length ? p.secretIssues.map(s => `${s.file}: ${s.snippet}`).join('; ') : '',
    impact: 'API Key 硬编码在代码中，一旦公开即被盗刷；git 历史中的密钥等于永久泄露。',
    fix: '密钥移入 .env.local（gitignore），代码从环境变量读取；已泄露的立即吊销' },
  { id: 'gitignore', pack: 'security', level: 'surface', severity: 'critical', name: '忽略规则',
    check: p => p.hasFile('.gitignore'),
    impact: '构建产物、密钥文件被纳入版本控制。',
    fix: '创建 .gitignore' },
  // === docs ===
  { id: 'readme', pack: 'docs', level: 'surface', severity: 'info', name: '项目说明',
    check: p => p.hasFile('README.md') || p.hasFile('readme.md'),
    impact: '打开项目不知道做什么、怎么跑。',
    fix: '创建 README.md' },
  { id: 'agents', pack: 'docs', level: 'surface', severity: 'warning', name: '协作规范',
    check: p => p.hasFile('AGENTS.md') || p.hasFile('CLAUDE.md') || p.hasFile('agent.md'),
    impact: '每次会话重新建立规则，行为不一致。',
    fix: '创建 AGENTS.md' },
  { id: 'retro', pack: 'docs', level: 'surface', severity: 'info', name: '复盘记录',
    check: p => p.hasFile('开发复盘.md') || p.hasFile('docs/复盘.md') || p.hasFile('项目记忆.md'),
    impact: '踩过的坑不沉淀，下次重新踩。',
    fix: '创建开发复盘.md' },
  // === compliance ===
  { id: 'license', pack: 'compliance', level: 'surface', severity: 'info', name: '开源许可',
    check: p => p.hasFile('LICENSE'),
    impact: '无许可证 = 默认保留所有权利。',
    fix: '添加 LICENSE' },
  { id: 'privacy', pack: 'compliance', level: 'surface', severity: 'warning', name: '隐私政策',
    check: p => !p.isPublic || p.hasFile('privacy.html') || p.hasFile('docs/privacy.md') || p.hasFile('pages/privacy.md'),
    impact: '收集用户数据但无隐私政策，违反个保法。',
    fix: '公开项目需添加隐私政策' },
  // === dependency ===
  { id: 'dep-lockfile', pack: 'deep', level: 'deep', severity: depSeverity, name: '依赖健康',
    applies: p => !!p.deps,
    check: p => !p.deps || p.deps.health === 'good',
    detail: depDetail, impact: depImpact, fix: depFix },
  // === complexity ===
  { id: 'code-complexity', pack: 'deep', level: 'deep', severity: p => p.complexity?.health === 'poor' ? 'warning' : 'info',
    name: '代码体量',
    applies: p => !!p.complexity && p.complexity.scannedFiles > 0,
    check: p => !p.complexity || p.complexity.health !== 'poor',
    detail: p => p.complexity?.scannedFiles ? `最大的文件 ${p.complexity.largestFile}（${p.complexity.largestLines} 行）· 超 500 行的文件 ${p.complexity.bigFileCount} 个 · 未完成的待办标记 ${p.complexity.todoCount} 处 · 共扫 ${p.complexity.scannedFiles} 个代码文件` : '',
    impact: '单个文件越长越难改——AI 每次只能看到局部，改一处容易碰坏别处；满篇待办标记说明留了不少没做完的活。',
    fix: '把超长文件按功能拆小；待办标记要么排期做完，要么删掉' },
];

/* ---------- 执行审计 ---------- */
function audit(root, packs) {
  const names = findProjects(root);
  const results = [];

  for (const name of names) {
    const p = scanProject(root, name);
    const findings = [];
    const passes = [];

    for (const rule of RULES) {
      if (!packs.includes(rule.pack)) continue;
      if (rule.applies && !rule.applies(p)) continue;
      const pass = rule.check(p);
      if (!pass) {
        const sev = typeof rule.severity === 'function' ? rule.severity(p) : rule.severity;
        findings.push({
          id: rule.id, severity: sev, name: rule.name,
          level: rule.level,
          detail: rule.detail ? rule.detail(p) : '',
          impact: typeof rule.impact === 'function' ? rule.impact(p) : rule.impact,
          fix: typeof rule.fix === 'function' ? rule.fix(p) : rule.fix,
        });
      } else if (rule.detail) {
        // 通过但有值得展示的深度信息
        const detail = rule.detail(p);
        if (detail) passes.push({ id: rule.id, name: rule.name, level: rule.level, detail });
      }
    }

    results.push({
      name,
      type: p.type,
      criticalCount: findings.filter(f => f.severity === 'critical').length,
      warningCount: findings.filter(f => f.severity === 'warning').length,
      infoCount: findings.filter(f => f.severity === 'info').length,
      findings,
      deepInfo: passes.filter(p2 => p2.level === 'deep'),
    });
  }
  return results;
}

/* ---------- 报告生成 ---------- */
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function generateReport(results, root, outDir, previous, trendResults) {
  const tc = results.reduce((a, r) => a + r.criticalCount, 0);
  const tw = results.reduce((a, r) => a + r.warningCount, 0);
  const ti = results.reduce((a, r) => a + r.infoCount, 0);
  const tp = results.length;

  const SC = { critical: '#c0392b', warning: '#d4a017', info: '#3498db', pass: '#27ae60' };
  const SB = { critical: '#fdf0ef', warning: '#fdf8e7', info: '#ebf5fb', pass: '#eafaf1' };
  const SL = { critical: '严重', warning: '警告', info: '建议', pass: '通过' };
  const trendIcon = { worse: '↑', better: '↓', stable: '→', new: '★', clean: '✓' };
  const trendColor = { worse: SC.critical, better: SC.pass, stable: '#6b7078', new: SC.info, clean: SC.pass };
  const trendLabel = { worse: '恶化', better: '改善', stable: '持平', new: '新项目', clean: '全部通过' };

  const trendSummary = trendResults ? `
    <div class="trend-banner">
      ${previous ? `对比上次（${previous.date}）：` : ''}
      ${trendResults.filter(r => r.trend === 'better').length} 个改善 ·
      ${trendResults.filter(r => r.trend === 'worse').length} 个恶化 ·
      ${trendResults.filter(r => r.trend === 'stable').length} 个持平
    </div>` : '';

  const projectRows = results.map((r, i) => {
    const tr = trendResults?.[i];
    const topSev = r.criticalCount ? 'critical' : r.warningCount ? 'warning' : r.infoCount ? 'info' : 'pass';
    return `
    <tr data-sev="${topSev}" data-c="${r.criticalCount}" data-w="${r.warningCount}" data-i="${r.infoCount}" data-name="${esc(r.name)}">
      <td><strong>${esc(r.name)}</strong><span class="ptype">${esc(TYPE_LABELS[r.type] || r.type)}</span></td>
      <td style="text-align:center">${r.criticalCount ? `<span class="sev critical">${r.criticalCount}</span>` : '<span class="sev pass">0</span>'}</td>
      <td style="text-align:center">${r.warningCount ? `<span class="sev warning">${r.warningCount}</span>` : '<span class="sev pass">0</span>'}</td>
      <td style="text-align:center">${r.infoCount ? `<span class="sev info">${r.infoCount}</span>` : '<span class="sev pass">0</span>'}</td>
      <td>${tr ? `<span class="trend" style="color:${trendColor[tr.trend]}">${trendIcon[tr.trend]} ${trendLabel[tr.trend]}</span>` : ''}</td>
      <td>${r.findings.slice(0, 4).map(f => `<span class="tag">${esc(f.name)}</span>`).join('')}${r.findings.length > 4 ? `<span class="tag">+${r.findings.length - 4}</span>` : ''}</td>
    </tr>`;}).join('');

  const projectCards = results.map((r, i) => {
    if (!r.findings.length && !r.deepInfo.length) return '';
    const tr = trendResults?.[i];
    const sevs = [...new Set(r.findings.map(f => f.severity))];
    const hasDeep = r.findings.some(f => f.level === 'deep');
    return `
    <div class="card" id="proj-${esc(r.name)}" data-sevs="${sevs.join(',')}" data-deep="${hasDeep ? 1 : 0}" data-c="${r.criticalCount}" data-w="${r.warningCount}" data-i="${r.infoCount}" data-name="${esc(r.name)}">
      <h3>
        ${esc(r.name)} <span class="ptype">${esc(TYPE_LABELS[r.type] || r.type)}</span>
        ${tr ? `<span class="trend" style="color:${trendColor[tr.trend]};font-size:14px">${trendIcon[tr.trend]} ${trendLabel[tr.trend]}</span>` : ''}
        ${tr?.newIssueIds?.length ? `<span class="trend-new">新增 ${tr.newIssueIds.length}</span>` : ''}
        ${tr?.resolvedIssueIds?.length ? `<span class="trend-fixed">修复 ${tr.resolvedIssueIds.length}</span>` : ''}
      </h3>
      ${r.findings.map(f => `
        <div class="finding sev-${f.severity}">
          <div class="finding-head">
            <span class="sev-badge ${f.severity}">${SL[f.severity]}</span>
            <strong>${esc(f.name)}</strong>
            ${f.level === 'deep' ? '<span class="deep-badge">深度</span>' : ''}
            ${tr?.newIssueIds?.includes(f.id) ? '<span class="new-badge">NEW</span>' : ''}
          </div>
          ${f.detail ? `<p class="detail">${esc(f.detail)}</p>` : ''}
          <p class="impact"><strong>影响</strong>：${esc(f.impact)}</p>
          ${f.fix ? `<p class="fix"><strong>建议</strong>：${esc(f.fix)}</p>` : ''}
        </div>`).join('')}
      ${r.deepInfo.length ? `
        <details><summary>深度分析数据</summary>
          ${r.deepInfo.map(d => `<p class="deep-info"><strong>${esc(d.name)}</strong>：${esc(d.detail)}</p>`).join('')}
        </details>` : ''}
    </div>`;}).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>工程纪律审计 · ${TODAY}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#f5f3ef;color:#1a1d21;line-height:1.7;padding:40px 20px}
  .container{max-width:960px;margin:0 auto}
  h1{font-size:28px;margin-bottom:4px}
  .meta{color:#6b7078;font-size:13px;margin-bottom:24px}
  .summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px}
  .stat{background:#fff;border:1px solid #ddd;border-radius:10px;padding:18px;text-align:center}
  .stat .num{font-size:36px;font-weight:800}
  .stat .label{font-size:13px;color:#6b7078}
  .stat.critical .num{color:${SC.critical}} .stat.warning .num{color:${SC.warning}}
  .stat.info .num{color:${SC.info}} .stat.projects .num{color:#1a1d21}
  .trend-banner{background:#fff;border:1px solid #ddd;border-left:3px solid #3498db;border-radius:0 10px 10px 0;padding:12px 18px;margin-bottom:24px;font-size:14px;color:#3d4248}
  h2{font-size:20px;margin:32px 0 14px;padding-top:16px;border-top:1px solid #ddd}
  table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #ddd;border-radius:8px;overflow:hidden}
  th{text-align:left;font-size:12px;color:#6b7078;border-bottom:2px solid #ddd;padding:10px 14px;letter-spacing:.06em}
  td{padding:10px 14px;border-bottom:1px solid #eee;font-size:14px}
  tr:hover td{background:#fafafa}
  .sev{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}
  .sev.critical{color:${SC.critical};background:${SB.critical}} .sev.warning{color:${SC.warning};background:${SB.warning}}
  .sev.info{color:${SC.info};background:${SB.info}} .sev.pass{color:#27ae60;background:#eafaf1}
  .tag{display:inline-block;font-size:12px;color:#6b7078;background:#f0ede8;border:1px solid #ddd;border-radius:4px;padding:1px 7px;margin:2px 4px 2px 0}
  .ptype{font-size:11px;color:#8a929c;margin-left:6px;border:1px solid #ddd;border-radius:4px;padding:0 5px}
  .trend{font-size:13px;font-weight:600;white-space:nowrap}
  .trend-new{font-size:11px;color:${SC.critical};background:${SB.critical};border-radius:4px;padding:1px 6px;margin-left:6px;font-weight:700}
  .trend-fixed{font-size:11px;color:#27ae60;background:#eafaf1;border-radius:4px;padding:1px 6px;margin-left:4px;font-weight:700}
  .card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:20px 22px;margin:14px 0}
  .card h3{font-size:17px;margin-bottom:12px;display:flex;align-items:center;flex-wrap:wrap;gap:6px}
  .finding{padding:10px 14px;margin:8px 0;border-radius:6px;border-left:3px solid}
  .finding.sev-critical{border-color:${SC.critical};background:${SB.critical}}
  .finding.sev-warning{border-color:${SC.warning};background:${SB.warning}}
  .finding.sev-info{border-color:${SC.info};background:${SB.info}}
  .finding-head{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap}
  .sev-badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;color:#fff}
  .sev-badge.critical{background:${SC.critical}} .sev-badge.warning{background:${SC.warning}} .sev-badge.info{background:${SC.info}}
  .deep-badge{font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;color:#8e44ad;background:#f4ecf7}
  .new-badge{font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;color:${SC.critical};background:#fff;border:1px solid ${SC.critical}}
  .detail{font-size:13px;color:#5a6470;margin:2px 0;font-style:italic}
  .impact,.fix{font-size:13.5px;color:#3d4248;margin:3px 0}
  .impact strong,.fix strong{color:#1a1d21}
  .deep-info{font-size:13px;color:#5a6470;margin:4px 0}
  details{margin-top:10px}
  summary{cursor:pointer;color:#6b7078;font-size:13px}
  .case-study{background:#fff;border:1px solid #ddd;border-left:3px solid #3498db;border-radius:0 10px 10px 0;padding:14px 18px;margin:10px 0;font-size:14px}
  .case-study .title{font-weight:700;margin-bottom:4px}
  .toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 12px}
  .toolbar .lbl{font-size:13px;color:#6b7078}
  .fbtn{font-size:13px;padding:4px 14px;border-radius:999px;border:1px solid #ddd;background:#fff;color:#3d4248;cursor:pointer}
  .fbtn:hover{border-color:#9aa2ac}
  .fbtn.on{background:#1a1d21;color:#fff;border-color:#1a1d21}
  .toolbar .sep{width:1px;height:18px;background:#ddd;margin:0 6px}
  @media print{body{padding:10px}.container{max-width:100%}.toolbar{display:none}}
  @media(max-width:768px){.summary{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="container">
  <h1>工程纪律审计报告</h1>
  <p class="meta">范围：${esc(root)} · ${tp} 个项目 · 检查维度：${RULE_PACKS.map(p2 => PACK_LABELS[p2] || p2).join('、')} · ${TODAY}</p>

  <div class="summary">
    <div class="stat critical"><div class="num">${tc}</div><div class="label">严重</div></div>
    <div class="stat warning"><div class="num">${tw}</div><div class="label">警告</div></div>
    <div class="stat info"><div class="num">${ti}</div><div class="label">建议</div></div>
    <div class="stat projects"><div class="num">${tp}</div><div class="label">项目</div></div>
  </div>

  ${trendSummary}

  <h2>总览</h2>
  <div class="toolbar">
    <span class="lbl">筛选</span>
    <button class="fbtn on" data-f="all">全部</button>
    <button class="fbtn" data-f="critical">有严重</button>
    <button class="fbtn" data-f="warning">有警告</button>
    <button class="fbtn" data-f="info">仅建议</button>
    <span class="sep"></span>
    <span class="lbl">排序</span>
    <button class="fbtn on" data-s="sev">按严重度</button>
    <button class="fbtn" data-s="name">按名称</button>
  </div>
  <table>
    <thead><tr><th>项目</th><th style="text-align:center;width:50px">严重</th><th style="text-align:center;width:50px">警告</th><th style="text-align:center;width:50px">建议</th><th style="width:96px">趋势</th><th>缺失项</th></tr></thead>
    <tbody>${projectRows}</tbody>
  </table>

  <h2>详细发现（含深度分析）</h2>
  <div class="toolbar">
    <span class="lbl">筛选</span>
    <button class="fbtn on" data-f="all">全部</button>
    <button class="fbtn" data-f="critical">严重</button>
    <button class="fbtn" data-f="warning">警告</button>
    <button class="fbtn" data-f="deep">深度发现</button>
  </div>
  <div id="cards">${projectCards || '<p style="color:#27ae60">全部通过。</p>'}</div>

  <h2>典型影响案例</h2>
  <div class="case-study"><div class="title">无版本控制的代价</div>某项目七轮视觉迭代后需回退到第三版，但没有提交记录，只能靠截图对比还原。加回滚点后，同类问题通过对比两次提交的改动，30 秒内定位。</div>
  <div class="case-study"><div class="title">测试全绿但真机白屏</div>某项目 109 个单测全部通过，浏览器打开整页白屏——组件代码在某个条件下提前结束，后续初始化没执行，而单测恰好没覆盖这条路径。此后真实浏览器走查成为完成定义的一部分。</div>
  <div class="case-study"><div class="title">同一时区问题出现四次</div>UTC 与本地时间混用导致"晚上 8 点后今天变明天"。同一项目修过后，下一个项目原样复现——根源是日期工具没有收口。</div>
  <div class="case-study"><div class="title">密钥进 git 的不可逆性</div>硬编码的密钥一旦提交，即使后续删除，历史中仍可恢复。等于永久泄露。唯一补救是立刻吊销换新。预防成本为零，补救成本极高。</div>
  <div class="case-study"><div class="title">规范从不更新的退化</div>某项目的协作规范创建后零更新，规则从未随实际教训增长，最终形同虚设——AI 行为与规范完全脱节。</div>
</div>
<script>
(function(){
  var tbody = document.querySelector('table tbody');
  if (!tbody) return;
  var rows = [].slice.call(tbody.children);
  var cards = [].slice.call(document.querySelectorAll('#cards .card'));
  var curF = 'all', curS = 'sev';
  function score(el){ return (+el.getAttribute('data-c')||0)*100 + (+el.getAttribute('data-w')||0)*10 + (+el.getAttribute('data-i')||0); }
  function bySev(a,b){ return score(b) - score(a); }
  function byName(a,b){ return (a.getAttribute('data-name')||'').localeCompare(b.getAttribute('data-name')||''); }
  function apply(){
    rows.forEach(function(r){
      r.style.display = (curF === 'all' || r.getAttribute('data-sev') === curF) ? '' : 'none';
    });
    cards.forEach(function(c){
      var sevs = (c.getAttribute('data-sevs') || '').split(',');
      var show = curF === 'all' || (curF === 'deep' ? c.getAttribute('data-deep') === '1' : sevs.indexOf(curF) > -1);
      c.style.display = show ? '' : 'none';
    });
    var cmp = curS === 'sev' ? bySev : byName;
    rows.sort(cmp).forEach(function(r){ tbody.appendChild(r); });
    cards.slice().sort(cmp).forEach(function(c){ c.parentNode.appendChild(c); });
  }
  document.querySelectorAll('.fbtn').forEach(function(btn){
    btn.addEventListener('click', function(){
      var g = btn.parentNode.querySelectorAll('.fbtn');
      if (btn.hasAttribute('data-f')) { curF = btn.getAttribute('data-f'); g.forEach(function(b){ if (b.hasAttribute('data-f')) b.classList.remove('on'); }); }
      else { curS = btn.getAttribute('data-s'); g.forEach(function(b){ if (b.hasAttribute('data-s')) b.classList.remove('on'); }); }
      btn.classList.add('on');
      apply();
    });
  });
  apply();
})();
</script>
</body>
</html>`;
}

/* ---------- 修复执行 ---------- */
function executeFixes(root, results, items) {
  // 模板目录：优先用本包自带的，其次找 AIMASTER 布局
  const templateDir = fs.existsSync(path.join(__dirname, '..', 'templates'))
    ? path.join(__dirname, '..', 'templates')
    : path.join(root, 'AIMASTER', 'starter', 'templates');
  const fixes = [];
  for (const r of results) {
    const dir = path.join(root, r.name);
    if (items.includes('git') && !fs.existsSync(path.join(dir, '.git'))) {
      try {
        sh(`git init -q`, dir);
        if (!fs.existsSync(path.join(dir, '.gitignore')))
          fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env.local\n*.pem\n*.key\ndist/\nbuild/\n__pycache__/\n*.pyc\n.DS_Store\nThumbs.db\n*.log\n.cache/\n');
        sh(`git add -A`, dir, 10000);
        sh(`git commit -q -m "init: 建立回滚基线"`, dir, 10000);
        fixes.push(`${r.name}: git init`);
      } catch (e) { fixes.push(`${r.name}: git init 失败`); }
    }
    if (items.includes('agents') && !fs.existsSync(path.join(dir, 'AGENTS.md')) && !fs.existsSync(path.join(dir, 'CLAUDE.md'))) {
      const skel = path.join(templateDir, 'AGENTS-skeleton.md');
      if (fs.existsSync(skel)) { fs.copyFileSync(skel, path.join(dir, 'AGENTS.md')); fixes.push(`${r.name}: AGENTS.md`); }
    }
    if (items.includes('gitignore') && !fs.existsSync(path.join(dir, '.gitignore'))) {
      fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env.local\n*.pem\n*.key\ndist/\nbuild/\n__pycache__/\n*.pyc\n.DS_Store\nThumbs.db\n*.log\n.cache/\n');
      fixes.push(`${r.name}: .gitignore`);
    }
  }
  return fixes;
}

/* ---------- 自定义规则加载 ---------- */
const CUSTOM_FILE = get('--custom-rules', '');
if (CUSTOM_FILE) {
  const arr = readJSON(CUSTOM_FILE);
  if (!Array.isArray(arr)) {
    console.error('自定义规则文件格式不对：需要是一个 JSON 数组，每条含 id/name/files/severity/impact/fix');
    process.exit(2);
  }
  const customRules = arr.map(r => ({
    id: r.id || 'custom-' + (r.name || '').slice(0, 8),
    pack: 'custom', level: 'surface',
    severity: r.severity || 'warning',
    name: r.name || r.id || '自定义检查',
    check: p => r.mustExist === false
      ? !(r.files || []).some(f => p.hasFile(f))
      : (r.files || []).every(f => p.hasFile(f)),
    impact: r.impact || '自定义检查未通过。',
    fix: r.fix || '',
  }));
  RULES.push(...customRules);
  RULE_PACKS.push('custom');
  console.log(`已加载 ${customRules.length} 条自定义规则（${CUSTOM_FILE}）`);
}

/* ---------- 主流程 ---------- */
const packs = RULE_PACKS.filter(Boolean);
const KNOWN_PACKS = ['core', 'security', 'docs', 'compliance', 'deep', 'custom'];
const unknownPacks = packs.filter(p2 => !KNOWN_PACKS.includes(p2));
if (unknownPacks.length) console.error(`忽略未知的规则包：${unknownPacks.join(', ')}（可用：${KNOWN_PACKS.join(', ')}）`);
const results = audit(ROOT, packs);
if (!results.length) {
  console.error(`提示：在 ${ROOT} 下没找到可识别的项目（认 package.json / requirements.txt / go.mod / Cargo.toml / index.html 这些标志）。检查 --root 是否指对了。`);
}

// 时间维度
const previous = loadPreviousAudit(OUT_BASE);
const trendResults = previous ? computeTrend(results, previous.data) : null;

// 输出
const outDir = path.join(OUT_BASE, TODAY);
fs.mkdirSync(outDir, { recursive: true });
const html = generateReport(results, ROOT, outDir, previous, trendResults);
fs.writeFileSync(path.join(outDir, 'index.html'), html);
fs.writeFileSync(path.join(outDir, 'audit-data.json'), JSON.stringify(results, null, 2));

// 摘要
const tc = results.reduce((a,r) => a + r.criticalCount, 0);
const tw = results.reduce((a,r) => a + r.warningCount, 0);
const deepCount = results.reduce((a,r) => a + r.findings.filter(f => f.level === 'deep').length, 0);
console.log(`\n审计完成 v2.1：${results.length} 个项目 · ${tc} 严重 · ${tw} 警告 · ${deepCount} 项深度发现`);
if (previous) console.log(`趋势对比：上次审计 ${previous.date}`);
console.log(`报告：${path.join(outDir, 'index.html')}\n`);

// 修复
if (FIX_ITEMS.length && CONFIRM) {
  const fixes = executeFixes(ROOT, results, FIX_ITEMS);
  fixes.forEach(f => console.log('  ' + f));
} else if (FIX_ITEMS.length) {
  console.log(`待修复（加 --confirm 执行）：${FIX_ITEMS.join(', ')}`);
}

// CI 门禁：有严重问题就返回非零退出码，供定时任务/自动化判断
if (args.includes('--ci')) {
  const failed = results.filter(r => r.criticalCount > 0);
  if (failed.length) {
    console.error(`[门禁未通过] ${failed.length} 个项目有严重问题：${failed.map(r => r.name).join('、')}`);
    process.exit(1);
  }
  console.log('[门禁通过] 没有严重问题');
}
