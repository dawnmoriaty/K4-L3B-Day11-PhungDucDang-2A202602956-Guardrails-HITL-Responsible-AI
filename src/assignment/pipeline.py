"""
Checkpoint 3 — Defense-in-depth pipeline assembly.

Wire rate limiter + lab guardrails + audit + monitoring + egress.
You may use Google ADK plugins, LangGraph, NeMo, or pure Python.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from guardrails.input_guardrails import InputGuardrailPlugin
from guardrails.output_guardrails import OutputGuardrailPlugin

# 1. Danh sách domain HTTPS nội bộ được cấp phép
TRUSTED_EGRESS_HOSTS = {
    "api.vinbank.example",
    "cases.vinbank.example",
    "api.vinbank.com",
    "payments.vinbank.com",
}

# 2. Phân loại các nhóm dữ liệu nhạy cảm cấm xuất ra ngoài
SENSITIVE_PATTERNS = {
    "credentials": [
        r"\badmin123\b",
        r"(?:password|mật\s*khẩu)\s*[:=]\s*\S+",
        r"\bpassword\b",
    ],
    "secrets": [
        r"sk-[a-zA-Z0-9-]{8,}",
        r"sk-vinbank-secret-2024",
        r"\bapi_key\b",
    ],
    "infrastructure": [
        r"db\.vinbank\.internal(?::\d+)?",
        r"\bdb_host\b",
        r"localhost:\d+",
        r"127\.0\.0\.1",
    ],
    "pii_phone": [
        r"\b0\d{9,10}\b",
    ],
    "pii_email": [
        r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}",
    ],
}


def is_egress_allowed(destination: str, payload: str) -> bool:
    """Enforce a destination allowlist before any data leaves the agent.

    Return ``True`` only for an approved VinBank HTTPS endpoint and ordinary
    banking payload. Return ``False`` for unknown domains and payloads that
    contain a password, API key, database host, phone number or email address.
    Do not let the LLM's prose decide this policy.
    """
    # 1. Validate destination: bắt buộc giao thức HTTPS và domain tin cậy
    try:
        parsed = urlparse(destination)
        if parsed.scheme != "https":
            return False
        if parsed.hostname not in TRUSTED_EGRESS_HOSTS:
            return False
    except Exception:
        return False

    # 2. Validate payload: duyệt qua từng nhóm dữ liệu nhạy cảm
    for category, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return False

    return True

def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = False,
) -> list:
    """Return an ordered list of plugins / layers:

    1. RateLimitPlugin
    2. InputGuardrailPlugin  (from guardrails.input_guardrails)
    3. OutputGuardrailPlugin  (from guardrails.output_guardrails)
       (LLM-as-Judge / NeMo are optional)

    Audit/monitoring can be plugins or side observers — document your choice.
    The action gateway calls ``is_egress_allowed`` separately before any sink.
    """
    return [
        RateLimitPlugin(max_requests=max_requests, window_seconds=window_seconds),
        InputGuardrailPlugin(),
        OutputGuardrailPlugin(use_llm_judge=use_llm_judge),
    ]


def build_observability():
    """Return (AuditLogPlugin(), MonitoringAlert())."""
    return AuditLogPlugin(), MonitoringAlert()


async def run_assignment_suite(pipeline) -> dict:
    """Run Tests 1–4 from CHECKPOINTS.md (Checkpoint 3) and
    return a dict matching schemas/results.schema.json.

    Write under **repo-root** ``outputs/`` (not ``src/outputs/``), e.g.::

        root = Path(__file__).resolve().parents[2]
        (root / "outputs" / "results.json").write_text(...)

    Files:
      <repo>/outputs/results.json
      <repo>/outputs/audit_log.json   (via AuditLogPlugin.export_json)
      <repo>/outputs/metrics.json     (via MonitoringAlert.export_json)
    """
    raise NotImplementedError("Implement run_assignment_suite")
