#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMP 计算日志解析脚本。改顶部配置后直接运行，不使用命令行参数解析。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ==================== 配置区：只改这里 ====================

INPUT_LOG = Path("/path/to/collected.log")
OUTPUT_PY = Path("/path/to/calc.py")

# 预设输入来源。例：{"w0": "plain", "w1": "key0"}
SEEDS: dict[str, str] = {
    # "w0": "plain",
    # "w1": "key0",
}

WIDTH = 32                    # 32 或 64
FINAL_LOC: Optional[str] = None  # 例如 "w8"；None 表示返回最后一个 vN
COLLAPSE_MOV = False          # True：mov 不生成新 vN，只更新映射
ASSERT_TRACE = True           # 根据日志写回值生成 assert

# 数值回溯策略：
# "none"   不按数值回溯
# "reg"    只检查当前寄存器绑定，默认推荐
# "global" 扫描最近变量，容易误引用，只在需要时打开
VALUE_BACKTRACK = "reg"
GLOBAL_WINDOW = 10            # global 回溯扫描最近多少个 vN；0 表示全部

# 读操作数没有匹配到已有 vN 时：
# "hex"   使用日志里的实际 hex 值
# "input" 生成 in_xxx 输入变量
UNKNOWN_READ = "hex"

# True 会把 w8/x8/b8 统一当成 r8；默认 False，保留原始寄存器名。
ALIAS_WIDTH_REGS = False

# ==================== 逻辑区：一般不用改 ====================

SUPPORTED = {
    "eor", "add", "sub", "mul", "and", "orr", "lsl", "lsr", "neg", "ror", "mov",
    "adds", "subs", "ands",
}
BINARY_OPS = {
    "eor": "^", "add": "+", "sub": "-", "mul": "*", "and": "&", "orr": "|",
    "adds": "+", "subs": "-", "ands": "&",
}
SHIFT_OPS = {"lsl": "<<", "lsr": ">>"}
VAL_RE = re.compile(r"\(([rw])\)([A-Za-z][A-Za-z0-9]*)=(0x[0-9a-fA-F]*)")
TRACE_ID_RE = re.compile(r"^\s*([0-9a-fA-F]+)\|")
HANDLER_RE = re.compile(r"\[\s*(0x[0-9a-fA-F]+)")
IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")


@dataclass
class TraceInst:
    line_no: int
    raw: str
    trace_id: str
    handler: str
    mnemonic: str
    operands: List[str]
    reads: Dict[str, int]
    writes: Dict[str, int]


@dataclass
class Statement:
    name: str
    expr: str
    raw_expr: str
    actual: Optional[int]
    comment: str


def safe_int(v: str) -> int:
    return 0 if not v or v == "0x" else int(v, 16)


def split_operands(text: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in text:
        if ch in "[{(":
            depth += 1
        elif ch in "]})" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            part = "".join(cur).strip()
            if part:
                parts.append(part)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_trace_line(line: str, line_no: int) -> Optional[TraceInst]:
    raw = line.rstrip("\n")
    vals = VAL_RE.findall(raw)
    reads = {reg.lower(): safe_int(val) for rw, reg, val in vals if rw == "r"}
    writes = {reg.lower(): safe_int(val) for rw, reg, val in vals if rw == "w"}

    head = re.split(r"\s+\([rw]\)", raw, 1)[0].split("//", 1)[0].split(";", 1)[0].strip()
    if not head or head.endswith(":"):
        return None

    found = None
    for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9_.]*)\b", head):
        base = m.group(1).lower().split(".", 1)[0]
        if base in SUPPORTED:
            found = (base, m.end())
            break
    if not found:
        return None

    mnemonic, pos = found
    operands = [x.lower() for x in split_operands(head[pos:].strip())]
    if not operands:
        return None

    trace_m = TRACE_ID_RE.search(raw)
    handler_m = HANDLER_RE.search(raw)
    trace_id = trace_m.group(1) if trace_m else str(line_no)
    handler = handler_m.group(1) if handler_m else ""
    return TraceInst(line_no, raw, trace_id, handler, mnemonic, operands, reads, writes)


def is_imm(op: str) -> bool:
    x = op.strip()
    if x.startswith("#"):
        x = x[1:]
    return bool(re.fullmatch(r"[-+]?(?:0x[0-9a-fA-F]+|\d+)", x))


def fmt_imm(op: str) -> str:
    x = op.strip()
    if x.startswith("#"):
        x = x[1:]
    return x.lower()


def loc_key(op: str, alias_width_regs: bool = False) -> str:
    x = op.strip().lower().replace("#", "")
    if x in {"wzr", "xzr"}:
        return "zero"
    if alias_width_regs:
        m = re.match(r"^[wxbhsdq]([0-9]+)$", x)
        if m:
            return f"r{m.group(1)}"
    return x


def sanitize_var(name: str) -> str:
    out = re.sub(r"\W+", "_", name.strip().lower()).strip("_") or "input"
    if out[0].isdigit():
        out = "in_" + out
    if out in {"and", "or", "not", "if", "else", "def", "return", "in", "is"}:
        out = "in_" + out
    return out


def symbols_from_expr(expr: str) -> List[str]:
    keywords = {"mask", "u32", "u64", "ror32", "ror64", "return", "def"}
    names: List[str] = []
    for ident in IDENT_RE.findall(expr):
        if ident in keywords or re.fullmatch(r"v\d+", ident):
            continue
        if ident not in names and not re.fullmatch(r"x?[0-9a-fA-F]+", ident):
            names.append(ident)
    return names


class LogParser:
    def __init__(self):
        self.width = WIDTH
        self.collapse_mov = COLLAPSE_MOV
        self.value_backtrack = VALUE_BACKTRACK
        self.global_window = GLOBAL_WINDOW
        self.unknown_read = UNKNOWN_READ
        self.alias_width_regs = ALIAS_WIDTH_REGS
        self.assert_trace = ASSERT_TRACE
        self.env: Dict[str, str] = {"zero": "0"}
        self.reg_to_var: Dict[str, str] = {}
        self.var_to_val: Dict[str, int] = {}
        self.inputs: Dict[str, str] = {}
        self.statements: List[Statement] = []
        self.counter = 0
        self.warnings: List[str] = []

    @property
    def mask_name(self) -> str:
        return f"u{self.width}"

    @property
    def ror_name(self) -> str:
        return f"ror{self.width}"

    def seed(self, loc: str, expr: str) -> None:
        key = loc_key(loc, self.alias_width_regs)
        self.env[key] = expr
        self.reg_to_var[key] = expr
        for name in symbols_from_expr(expr):
            self.inputs[name] = name

    def find_var_by_value(self, val: int, preferred: Optional[str]) -> Optional[str]:
        if self.value_backtrack in {"reg", "global"} and preferred and self.var_to_val.get(preferred) == val:
            return preferred
        if self.value_backtrack != "global":
            return None

        items = list(self.var_to_val.items())
        if self.global_window > 0:
            items = items[-self.global_window:]
        hits = [name for name, old_val in items if old_val == val]
        if not hits:
            return None
        if len(hits) > 1:
            self.warnings.append(f"数值 {hex(val)} 回溯命中多个变量 {hits}，已选最近的 {hits[-1]}，需要人工确认是否误引用")
        return hits[-1]

    def src_expr(self, operand: str, inst: TraceInst) -> str:
        op = operand.strip().lower()
        if not op:
            return "0"
        if op in {"wzr", "xzr"}:
            return "0"
        if is_imm(op):
            return fmt_imm(op)

        key = loc_key(op, self.alias_width_regs)
        if key in inst.reads:
            val = inst.reads[key]
            preferred = self.reg_to_var.get(key)
            found = self.find_var_by_value(val, preferred)
            if found:
                return found
            if key in self.env and not re.fullmatch(r"v\d+", self.env[key]):
                return self.env[key]
            if self.unknown_read == "input":
                name = sanitize_var(f"in_{key}")
                self.inputs[name] = name
                return name
            return hex(val)

        if key in self.env:
            return self.env[key]

        name = sanitize_var(f"in_{key}")
        self.env[key] = name
        self.inputs[name] = name
        return name

    def shift_amount(self, expr: str) -> str:
        return f"({expr} & 0x{self.width - 1:x})"

    def make_expr(self, inst: TraceInst) -> Tuple[str, str]:
        m = inst.mnemonic
        ops = inst.operands
        if m in BINARY_OPS:
            if len(ops) < 3:
                raise ValueError("需要 dest, src1, src2")
            left = self.src_expr(ops[1], inst)
            right = self.src_expr(ops[2], inst)
            if len(ops) >= 4 and ops[3].startswith(("lsl", "lsr")):
                st = ops[3].split()
                if len(st) >= 2:
                    sop = "<<" if st[0] == "lsl" else ">>"
                    amount = self.shift_amount(self.src_expr(st[1], inst))
                    right = f"({self.mask_name}({right}) >> {amount})" if sop == ">>" else f"({right} << {amount})"
            return f"{left} {BINARY_OPS[m]} {right}", ops[0]
        if m in SHIFT_OPS:
            if len(ops) < 3:
                raise ValueError("需要 dest, src, shift")
            src = self.src_expr(ops[1], inst)
            amount = self.shift_amount(self.src_expr(ops[2], inst))
            return (f"{self.mask_name}({src}) >> {amount}" if m == "lsr" else f"{src} << {amount}"), ops[0]
        if m == "ror":
            if len(ops) < 3:
                raise ValueError("需要 dest, src, amount")
            return f"{self.ror_name}({self.src_expr(ops[1], inst)}, {self.src_expr(ops[2], inst)})", ops[0]
        if m == "neg":
            if len(ops) < 2:
                raise ValueError("需要 dest, src")
            return f"-{self.src_expr(ops[1], inst)}", ops[0]
        if m == "mov":
            if len(ops) < 2:
                raise ValueError("需要 dest, src")
            return self.src_expr(ops[1], inst), ops[0]
        raise ValueError(f"不支持指令 {m}")

    def process(self, inst: TraceInst) -> None:
        try:
            raw_expr, dest = self.make_expr(inst)
        except ValueError as exc:
            self.warnings.append(f"第 {inst.line_no} 行：跳过 {inst.raw.strip()}（{exc}）")
            return

        dest_key = loc_key(dest, self.alias_width_regs)
        actual = inst.writes.get(dest_key)
        if dest_key == "zero":
            return

        if inst.mnemonic == "mov" and self.collapse_mov:
            self.env[dest_key] = raw_expr
            self.reg_to_var[dest_key] = raw_expr
            if actual is not None and re.fullmatch(r"v\d+", raw_expr):
                self.var_to_val[raw_expr] = actual
            return

        self.counter += 1
        name = f"v{self.counter}"
        expr = f"{self.mask_name}({raw_expr})"
        detail = f"[{inst.trace_id}]"
        if inst.handler:
            detail += f" {inst.handler}"
        detail += f" {inst.mnemonic}"
        if actual is not None:
            detail += f" -> {hex(actual)}"
        self.statements.append(Statement(name=name, expr=expr, raw_expr=raw_expr, actual=actual, comment=detail))
        self.env[dest_key] = name
        self.reg_to_var[dest_key] = name
        if actual is not None:
            self.var_to_val[name] = actual

    def emit_python(self) -> str:
        mask = (1 << self.width) - 1
        input_names = sorted(self.inputs)
        if FINAL_LOC:
            final_expr = self.env.get(loc_key(FINAL_LOC, self.alias_width_regs), sanitize_var(f"in_{FINAL_LOC}"))
        elif self.statements:
            final_expr = self.statements[-1].name
        else:
            final_expr = "0"

        out: List[str] = []
        out.append("#!/usr/bin/env python3")
        out.append("# -*- coding: utf-8 -*-")
        out.append(f"MASK = 0x{mask:x}")
        out.append("")
        out.append(f"def {self.mask_name}(x):")
        out.append("    return x & MASK")
        out.append("")
        out.append(f"def {self.ror_name}(x, n):")
        out.append(f"    n &= 0x{self.width - 1:x}")
        out.append(f"    x = {self.mask_name}(x)")
        out.append(f"    return {self.mask_name}((x >> n) | (x << (({self.width} - n) & 0x{self.width - 1:x})))")
        out.append("")
        out.append(f"def calc({', '.join(input_names)}):")
        if not self.statements:
            out.append("    return 0")
        for st in self.statements:
            out.append(f"    {st.name} = {st.expr}  # {st.comment}")
            if self.assert_trace and st.actual is not None:
                out.append(f"    assert {st.name} == {hex(st.actual)}, 'trace {st.comment} mismatch'")
        if self.statements:
            out.append(f"    out = {final_expr}")
            out.append("    return out")
        if self.warnings:
            out.append("")
            out.append("# 警告：")
            out.extend(f"# - {w}" for w in self.warnings)
        out.append("")
        return "\n".join(out)


def parse_log() -> str:
    parser = LogParser()
    for loc, expr in SEEDS.items():
        parser.seed(loc, expr)

    text = INPUT_LOG.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), 1):
        inst = parse_trace_line(line, line_no)
        if inst:
            parser.process(inst)

    output = parser.emit_python()
    OUTPUT_PY.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PY.write_text(output, encoding="utf-8")
    try:
        OUTPUT_PY.chmod(OUTPUT_PY.stat().st_mode | 0o111)
    except OSError:
        pass

    print(f"解析完成: {OUTPUT_PY}")
    print(f"生成语句数: {parser.counter}")
    if parser.warnings:
        print(f"警告数量: {len(parser.warnings)}")
    return output


if __name__ == "__main__":
    parse_log()
