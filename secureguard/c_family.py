"""Dependency-free C/C++ source-to-sink checks for common unsafe input flows.

This is a lightweight lexical adapter, not a replacement for a compiler parser.
It masks comments and literals before matching so examples in comments do not
normally become findings, and it preserves offsets for line/evidence reporting.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


FUNCTION = re.compile(
    r"(?m)^[ \t]*(?:[A-Za-z_]\w*(?:::\w+)?\s+|[A-Za-z_]\w*(?:::\w+)?\s*[*&]\s*)+"
    r"([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:const\s*)?(?:noexcept\s*)?\{"
)
CALL = re.compile(r"\b([A-Za-z_]\w*(?:::\w+)*|\w+)\s*\(")
SOURCE_CALLS = re.compile(r"\b(argv\s*\[|getenv\s*\(|recv\s*\(|recvfrom\s*\(|read\s*\(|fgets\s*\(|gets\s*\(|scanf\s*\(|fscanf\s*\(|fread\s*\()")
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
ASSIGN = re.compile(r"^\s*(?:const\s+)?[\w:*&<>\[\]\s]+?\b([A-Za-z_]\w*)\s*=(?!=)")


def mask_comments_and_literals(source: str) -> str:
    """Replace comments and string/char literals with spaces, preserving newlines."""
    chars = list(source)
    i, n = 0, len(source)

    def blank(start: int, end: int) -> None:
        for pos in range(start, end):
            if chars[pos] != "\n":
                chars[pos] = " "

    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(i, end)
            i = end
            continue
        if source[i] in ('"', "'"):
            quote = source[i]
            start, i = i, i + 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            blank(start, min(i, n))
            continue
        i += 1
    return "".join(chars)


def matching_brace(code: str, open_pos: int) -> int:
    depth = 0
    for pos in range(open_pos, len(code)):
        if code[pos] == "{":
            depth += 1
        elif code[pos] == "}":
            depth -= 1
            if depth == 0:
                return pos
    return len(code) - 1


def function_scopes(code: str) -> list[tuple[int, int, set[str]]]:
    scopes = []
    for match in FUNCTION.finditer(code):
        opening = match.end() - 1
        closing = matching_brace(code, opening)
        params = set()
        for param in match.group(2).split(","):
            words = IDENT.findall(param)
            if words and words != ["void"]:
                params.add(words[-1])
        scopes.append((opening, closing, params))
    # Ignore any accidental overlapping match inside an already recognized function.
    scopes.sort(key=lambda s: s[0])
    return [scope for i, scope in enumerate(scopes)
            if not any(parent[0] < scope[0] < parent[1] for parent in scopes[:i])]


def call_arguments(code: str, open_pos: int) -> list[tuple[int, int]]:
    depth, start, args = 0, open_pos + 1, []
    for pos in range(open_pos + 1, len(code)):
        char = code[pos]
        if char in "([{":
            depth += 1
        elif char in ")]}" :
            if char == ")" and depth == 0:
                if code[start:pos].strip():
                    args.append((start, pos))
                return args
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            args.append((start, pos))
            start = pos + 1
    return args


class CFamilyAnalyzer:
    def __init__(self, source: str, filename: str):
        self.source = source
        self.filename = filename
        self.code = mask_comments_and_literals(source)
        self.lines = source.splitlines()
        self.findings: list[dict[str, Any]] = []
        self.seen: set[tuple[int, str]] = set()

    def add(self, pos: int, cwe: str, title: str, reason: str, confidence: float = 0.7) -> None:
        line = self.code.count("\n", 0, pos) + 1
        key = (line, cwe)
        if key in self.seen:
            return
        self.seen.add(key)
        evidence = self.lines[line - 1].strip() if 1 <= line <= len(self.lines) else ""
        self.findings.append({
            "file": self.filename, "line": line, "cwe": cwe, "title": title,
            "evidence": evidence, "reason": reason,
            "recommendation": "Validate input and use a bounded or parameterized API; see the retrieved local CWE reference.",
            "confidence": confidence, "source": "c-family-taint-analysis",
        })

    @staticmethod
    def directly_untrusted(text: str) -> bool:
        return bool(SOURCE_CALLS.search(text) or re.search(r"\bstd\s*::\s*cin\s*>>", text))

    @staticmethod
    def has_tainted_identifier(text: str, names: set[str]) -> bool:
        return bool(names.intersection(IDENT.findall(text)))

    def analyze_scope(self, start: int, end: int, names: set[str]) -> None:
        scope = self.code[start:end]
        scope_offset = start
        original_scope = self.source[start:end]
        lines = scope.splitlines(keepends=True)
        original_lines = original_scope.splitlines(keepends=True)
        pos = scope_offset
        for index, masked_line in enumerate(lines):
            raw_line = original_lines[index] if index < len(original_lines) else masked_line
            # C/C++ input APIs write into output buffers rather than returning a value.
            for call in CALL.finditer(masked_line):
                call_name = call.group(1).split("::")[-1]
                call_open = pos + call.end() - 1
                ranges = call_arguments(self.code, call_open)
                args = [self.code[a:b] for a, b in ranges]
                output_index = 1 if call_name in {"recv", "recvfrom", "read"} else 0
                if call_name in {"fgets", "gets", "recv", "recvfrom", "read", "fread"} and output_index < len(args):
                    output_names = IDENT.findall(args[output_index])
                    if output_names:
                        names.add(output_names[-1])
                if call_name in {"strcpy", "strcat", "strncpy", "strncat", "sprintf", "snprintf", "memcpy", "memmove"} and len(args) > 1:
                    source_arg = args[1]
                    if self.directly_untrusted(source_arg) or self.has_tainted_identifier(source_arg, names):
                        destination_names = IDENT.findall(args[0])
                        if destination_names:
                            names.add(destination_names[-1])
            if re.search(r"\bstd\s*::\s*cin\s*>>\s*([A-Za-z_]\w*)", masked_line):
                names.update(re.findall(r"\bstd\s*::\s*cin\s*>>\s*([A-Za-z_]\w*)", masked_line))
            if re.search(r"\b(?:scanf|fscanf)\s*\(", masked_line):
                # scanf-family destinations are pointers; assume values read are untrusted.
                names.update(IDENT.findall(masked_line.split(")", 1)[0])[-2:])

            assignment = ASSIGN.search(masked_line)
            if assignment:
                lhs = assignment.group(1)
                rhs = masked_line[assignment.end():]
                if self.directly_untrusted(rhs) or self.has_tainted_identifier(rhs, names):
                    names.add(lhs)
                else:
                    names.discard(lhs)

            for call in CALL.finditer(masked_line):
                name = call.group(1).split("::")[-1]
                open_pos = pos + call.end() - 1
                args = call_arguments(self.code, open_pos)
                arg_texts = [self.code[a:b] for a, b in args]
                first = arg_texts[0] if arg_texts else ""
                tainted_first = self.directly_untrusted(first) or self.has_tainted_identifier(first, names)
                call_pos = pos + call.start()

                if name in {"gets", "strcpy", "strcat", "sprintf", "vsprintf"}:
                    self.add(call_pos, "CWE-120", f"Use of potentially unsafe {name}()",
                             f"{name}() does not provide a reliable destination-size bound; check whether input can exceed the destination.", 0.68)
                if name in {"system", "popen"} and tainted_first:
                    self.add(call_pos, "CWE-78", "Possible OS command injection",
                             "A command passed to a shell API contains an untrusted value.", 0.9)
                if name in {"printf", "fprintf", "syslog"} and tainted_first:
                    self.add(call_pos, "CWE-134", "Possible uncontrolled format string",
                             "A potentially untrusted value is used as the format string rather than as data.", 0.84)
                if name in {"memcpy", "memmove", "strncpy", "strncat"} and len(arg_texts) >= 3:
                    if self.directly_untrusted(arg_texts[2]) or self.has_tainted_identifier(arg_texts[2], names):
                        self.add(call_pos, "CWE-787", f"Potentially unbounded {name}() write",
                                 "The copy length may depend on untrusted input; validate it against the destination capacity.", 0.78)

            # scanf("%s") without a field width can overrun the destination buffer.
            for call in CALL.finditer(masked_line):
                if call.group(1).split("::")[-1] not in {"scanf", "fscanf", "sscanf"}:
                    continue
                open_pos = pos + call.end() - 1
                ranges = call_arguments(self.code, open_pos)
                if not ranges:
                    continue
                format_index = 1 if call.group(1).split("::")[-1] in {"fscanf", "sscanf"} else 0
                if format_index >= len(ranges):
                    continue
                raw_fmt = self.source[ranges[format_index][0]:ranges[format_index][1]]
                for spec in re.finditer(r"%(\d*)(?:hh|h|ll|l|L|z|j|t)?s", raw_fmt):
                    if not spec.group(1):
                        self.add(pos + call.start(), "CWE-120", "Unbounded scanf string conversion",
                                 "A %s conversion has no field width, so the input may exceed the destination buffer.", 0.88)
                        break

            pos += len(masked_line)

    def run(self) -> list[dict[str, Any]]:
        scopes = function_scopes(self.code)
        if not scopes:
            self.analyze_scope(0, len(self.code), set())
        else:
            for opening, closing, params in scopes:
                self.analyze_scope(opening + 1, closing, set(params))
        return sorted(self.findings, key=lambda f: (f["line"], f["cwe"]))


def analyze_c_family(path: Path) -> tuple[str, list[dict[str, Any]]]:
    source = path.read_text(encoding="utf-8", errors="replace")
    return source, CFamilyAnalyzer(source, str(path)).run()
