"""Tests for multi-language stack trace parsing."""

from incidentpilot.collectors.stacktrace import parse_stacktrace


def test_parse_go_panic() -> None:
    trace = (
        "panic: runtime error: invalid memory address or nil pointer dereference\n"
        "github.com/acme/shop/pkg/checkout.Charge(0x0)\n"
        "\t/app/pkg/checkout/checkout.go:114 +0x2c\n"
    )
    parsed = parse_stacktrace(trace)
    assert parsed is not None
    assert parsed.language == "go"
    assert "nil pointer" in parsed.error_message
    assert len(parsed.frames) == 1
    assert parsed.frames[0].file == "/app/pkg/checkout/checkout.go"
    assert parsed.frames[0].line == 114


def test_parse_python_traceback() -> None:
    trace = (
        "Traceback (most recent call last):\n"
        '  File "/srv/app/orders/processor.py", line 73, in submit\n'
        "    return total / count\n"
        "ZeroDivisionError: division by zero\n"
    )
    parsed = parse_stacktrace(trace)
    assert parsed is not None
    assert parsed.language == "python"
    assert parsed.error_type == "ZeroDivisionError"
    assert parsed.frames[0].file == "/srv/app/orders/processor.py"
    assert parsed.frames[0].line == 73
    assert parsed.frames[0].function == "submit"


def test_parse_node_stacktrace() -> None:
    trace = (
        "TypeError: Cannot read properties of undefined (reading 'id')\n"
        "    at processCheckout (/app/src/checkout.ts:42:17)\n"
    )
    parsed = parse_stacktrace(trace)
    assert parsed is not None
    assert parsed.language == "javascript"
    assert parsed.frames[0].file == "/app/src/checkout.ts"
    assert parsed.frames[0].line == 42
