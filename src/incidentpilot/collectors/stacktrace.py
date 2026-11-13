"""Multi-language stack trace parser."""

from __future__ import annotations

import re

from incidentpilot.models import ParsedStackTrace, StackFrame

# Go: "/app/pkg/checkout/checkout.go:114 +0x2c" or "\tpkg/checkout/checkout.go:114"
_GO_FRAME_RE = re.compile(r"^\s*(?P<file>[^\s:]+\.go):(?P<line>\d+)(?:\s+\+0x[0-9a-fA-F]+)?")
_GO_FUNC_RE = re.compile(r"^(?P<func>[a-zA-Z0-9_./*-]+)\([^)]*\)\s*$")
_GO_PANIC_RE = re.compile(r"^panic:\s*(?P<msg>.+)$")

# Python: '  File "/app/checkout.py", line 114, in handle_payment'
_PY_FRAME_RE = re.compile(
    r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<func>.+))?$'
)
_PY_ERR_RE = re.compile(r"^(?P<type>[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Panic)):\s*(?P<msg>.+)$")

# Node.js / TS: '    at processOrder (/app/src/checkout.ts:114:18)' or '    at /app/src/checkout.ts:114:18'
_NODE_FRAME_RE = re.compile(
    r"^\s*at\s+(?:(?P<func>[^\s(]+)\s+\()?(?P<file>[^():\n]+\.(?:js|ts|mjs|cjs|jsx|tsx)):(?P<line>\d+)(?::\d+)?\)?"
)

# Java: '    at com.acme.Checkout.charge(Checkout.java:114)'
_JAVA_FRAME_RE = re.compile(
    r"^\s*at\s+(?P<func>[\w.$<>]+)\((?P<file>[\w.$]+\.java):(?P<line>\d+)\)"
)

# Rust: '   at src/checkout.rs:114:9'
_RUST_FRAME_RE = re.compile(r"^\s*(?:at\s+)?(?P<file>[^\s:]+\.rs):(?P<line>\d+)(?::\d+)?")


def normalize_file_path(path: str) -> str:
    """Normalize OS separators and strip leading slashes/dots for matching."""
    cleaned = path.replace("\\", "/").strip()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def parse_stacktrace(text: str) -> ParsedStackTrace | None:
    """Parse a raw stack trace or error block into structured frames."""
    if not text or not text.strip():
        return None

    lines = text.splitlines()
    frames: list[StackFrame] = []
    error_type = ""
    error_message = ""
    language = "unknown"

    pending_go_func = ""

    for raw_line in lines:
        line = raw_line.rstrip()

        if not error_message:
            go_panic = _GO_PANIC_RE.match(line.strip())
            if go_panic:
                error_type = "panic"
                error_message = go_panic.group("msg").strip()
                language = "go"
                continue

            py_err = _PY_ERR_RE.match(line.strip())
            if py_err:
                error_type = py_err.group("type")
                error_message = py_err.group("msg").strip()
                continue

        # Python frame
        m_py = _PY_FRAME_RE.match(line)
        if m_py:
            language = "python"
            frames.append(
                StackFrame(
                    file=normalize_file_path(m_py.group("file")),
                    line=int(m_py.group("line")),
                    function=(m_py.group("func") or "").strip(),
                    language="python",
                    raw=line.strip(),
                )
            )
            continue

        # Go function line followed by Go file:line
        m_go_func = _GO_FUNC_RE.match(line.strip())
        if m_go_func and ("/" in m_go_func.group("func") or "." in m_go_func.group("func")):
            pending_go_func = m_go_func.group("func")
            continue

        m_go = _GO_FRAME_RE.match(line)
        if m_go:
            language = "go"
            frames.append(
                StackFrame(
                    file=normalize_file_path(m_go.group("file")),
                    line=int(m_go.group("line")),
                    function=pending_go_func,
                    language="go",
                    raw=line.strip(),
                )
            )
            pending_go_func = ""
            continue

        # Node / TypeScript
        m_node = _NODE_FRAME_RE.match(line)
        if m_node:
            if language == "unknown":
                language = "javascript"
            frames.append(
                StackFrame(
                    file=normalize_file_path(m_node.group("file")),
                    line=int(m_node.group("line")),
                    function=(m_node.group("func") or "").strip(),
                    language="javascript",
                    raw=line.strip(),
                )
            )
            continue

        # Java
        m_java = _JAVA_FRAME_RE.match(line)
        if m_java:
            language = "java"
            frames.append(
                StackFrame(
                    file=normalize_file_path(m_java.group("file")),
                    line=int(m_java.group("line")),
                    function=m_java.group("func"),
                    language="java",
                    raw=line.strip(),
                )
            )
            continue

        # Rust
        m_rust = _RUST_FRAME_RE.match(line)
        if m_rust:
            language = "rust"
            frames.append(
                StackFrame(
                    file=normalize_file_path(m_rust.group("file")),
                    line=int(m_rust.group("line")),
                    function="",
                    language="rust",
                    raw=line.strip(),
                )
            )
            continue

    if not frames and not error_message:
        return None

    if not error_message and lines:
        error_message = lines[0].strip()

    return ParsedStackTrace(
        error_type=error_type,
        error_message=error_message,
        language=language,
        frames=frames,
    )
