#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMP 计算日志收集脚本。改顶部配置后直接运行，不使用命令行参数解析。"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# ==================== 配置区：只改这里 ====================

INPUT_LOG = Path("/path/to/raw_vmp.log")
OUTPUT_LOG = Path("/path/to/collected.log")

# 当前任务自己从日志/分析结果收集 handler 地址，写在这里。
# 不要引用个人电脑上的历史脚本路径。
HANDLERS: dict[str, str] = {
    # "0x...": "ADD",
    # "0x...": "EOR",
}

# 只收集指定指令；空集合表示按 HANDLERS 或支持的计算指令收集。
ONLY_OPS: set[str] = set()
# ONLY_OPS = {"add", "eor", "ror"}

# 可选区间 marker；不需要就保持 None。
START_MARKER: Optional[str] = None
END_MARKER: Optional[str] = None

PRINT_STATS = True

# ==================== 逻辑区：一般不用改 ====================

SUPPORTED_OPS = {
    "eor", "add", "sub", "mul", "and", "orr", "lsl", "lsr", "neg", "ror", "mov",
    "adds", "subs", "ands",
}
HANDLER_IN_LINE_RE = re.compile(r"\[\s*(0x[0-9a-fA-F]+)")
HANDLER_PAIR_RE = re.compile(r"['\"]?(0x[0-9a-fA-F]+)['\"]?\s*[:=]\s*['\"]?([A-Za-z][A-Za-z0-9_]*)?['\"]?")
LINE_PAIR_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z][A-Za-z0-9_]*)?\s*(?:#.*)?$")


def norm_addr(addr: str) -> str:
    return hex(int(addr, 16))


def load_handler_file(path: Path) -> Dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    handlers: Dict[str, str] = {}

    # 兼容 Python dict / JSON 风格："0xf1db8": "ADD"
    for addr, op in HANDLER_PAIR_RE.findall(text):
        handlers[norm_addr(addr)] = (op or "").lower()

    # 兼容纯文本：0xf1db8 ADD
    for line in text.splitlines():
        m = LINE_PAIR_RE.match(line)
        if m:
            addr, op = m.groups()
            handlers[norm_addr(addr)] = (op or "").lower()
    return handlers


def select_interval(lines: Sequence[str], start: Optional[str], end: Optional[str]) -> List[Tuple[int, str]]:
    selected: List[Tuple[int, str]] = []
    active = start is None
    for idx, line in enumerate(lines, 1):
        if not active and start is not None and start in line:
            active = True
        if active:
            selected.append((idx, line))
        if active and end is not None and end in line:
            break
    return selected


def handler_addr_from_line(line: str) -> Optional[str]:
    m = HANDLER_IN_LINE_RE.search(line)
    if not m:
        return None
    try:
        return norm_addr(m.group(1))
    except ValueError:
        return None


def mnemonic_from_line(line: str) -> Optional[str]:
    head = re.split(r"\s+\([rw]\)", line, 1)[0]
    for tok in re.findall(r"\b[A-Za-z][A-Za-z0-9_.]*\b", head):
        base = tok.lower().split(".", 1)[0]
        if base in SUPPORTED_OPS:
            return base
    return None


def should_keep(line: str, handlers: Dict[str, str], only_ops: set[str]) -> bool:
    addr = handler_addr_from_line(line)
    op = mnemonic_from_line(line)

    if handlers:
        if addr not in handlers:
            return False
        mapped_op = handlers.get(addr, "")
        if only_ops:
            return (mapped_op in only_ops) or (op in only_ops)
        return True

    if only_ops:
        return op in only_ops
    return op in SUPPORTED_OPS


def collect_lines() -> list[str]:
    handlers = {norm_addr(k): v.lower() for k, v in HANDLERS.items()}
    text = INPUT_LOG.read_text(encoding="utf-8", errors="replace")
    interval = select_interval(text.splitlines(True), START_MARKER, END_MARKER)
    kept: list[str] = []
    for _, line in interval:
        if should_keep(line, handlers, {x.lower() for x in ONLY_OPS}):
            kept.append(line if line.endswith("\n") else line + "\n")

    OUTPUT_LOG.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_LOG.write_text("".join(kept), encoding="utf-8")

    if PRINT_STATS:
        print(f"收集完成: {OUTPUT_LOG}")
        print(f"收集行数: {len(kept)} / 区间行数: {len(interval)} / handler数: {len(handlers)}")
    return kept


if __name__ == "__main__":
    collect_lines()
