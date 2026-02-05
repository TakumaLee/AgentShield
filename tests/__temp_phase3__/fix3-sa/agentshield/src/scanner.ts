// Pattern for chmod 777 detection
const PATTERNS = [
  /chmod\s+777/i,
  /child_process/,
];