/* 重建演示用的两个假项目：在 demo/ 目录下运行 node _gen.cjs，会生成 legacy-app 和 well-kept */
const fs = require('fs');
const path = require('path');
const w = (p, c) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c); };

// —— 演示项目 A：缺乏约束的旧项目 ——
w('legacy-app/package.json', JSON.stringify({
  name: 'legacy-app', version: '0.1.0',
  dependencies: { express: '^4.18.2', lodash: '*', axios: 'latest' },
}, null, 2));

const bigFile = '// 旧的主逻辑，一直没有拆分\n\n' +
  Array.from({ length: 620 }, (_, i) =>
    i % 25 === 0 ? `  // TODO: 这段逻辑之后要重写（第${i}段）` : `  step${i}();`
  ).join('\n') + '\n';
w('legacy-app/src/app.js', bigFile);
w('legacy-app/run.bat', 'node src/app.js\r\n');

// —— 演示项目 B：守规矩的项目 ——
w('well-kept/package.json', JSON.stringify({
  name: 'well-kept', version: '1.0.0',
  scripts: { test: 'node tools/verify.js' },
}, null, 2));
w('well-kept/.gitignore', 'node_modules/\n.env.local\n*.log\ndist/\n');
w('well-kept/README.md', '# well-kept\n\n演示用的小项目：文档齐全、有验证脚本。\n\n## 运行\n\n    node tools/verify.js\n');
w('well-kept/AGENTS.md', '# 协作规范\n\n1. 说人话，不造新词。\n2. 先 spec 后代码。\n3. 改动前先跑 tools/verify.js，全绿再提交。\n');
w('well-kept/docs/spec.md', [
  '# 需求：well-kept', '',
  '## 范围', '演示 PULSE 的整洁项目长什么样。', '',
  '## 明确不做什么', '不做网络请求、不做界面。', '',
  '## 验收标准', '    node tools/verify.js', '输出两行 PASS。', '',
  '## 失败条款', '若两周内无人使用，归档。', '',
].join('\n'));
w('well-kept/tools/verify.js', [
  'function check(name, actual, expected) {',
  "  if (actual !== expected) { console.error(name + ' FAIL'); process.exit(1); }",
  "  console.log(name + ' PASS');",
  '}',
  "check('加法', 1 + 1, 2);",
  "check('拼接', 'a' + 'b', 'ab');",
  '',
].join('\n'));

console.log('demo fixtures created');
