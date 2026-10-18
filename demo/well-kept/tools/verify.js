function check(name, actual, expected) {
  if (actual !== expected) { console.error(name + ' FAIL'); process.exit(1); }
  console.log(name + ' PASS');
}
check('加法', 1 + 1, 2);
check('拼接', 'a' + 'b', 'ab');
