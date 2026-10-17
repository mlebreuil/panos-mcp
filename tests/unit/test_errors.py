from __future__ import annotations

import ssl

import httpx
import pytest
from defusedxml import ElementTree as SafeET

from panos_mcp.client.errors import from_error_response, from_exception
from panos_mcp.models.common import ErrorCode


def err(body: str, keygen: bool = False) -> ErrorCode:
    info = from_error_response(SafeET.fromstring(body), keygen=keygen).info
    assert info.message and info.hint
    assert "SECRET" not in info.message + info.hint
    return info.code


def test_403_keygen_is_auth_failed() -> None:
    body = '<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>'
    assert err(body, keygen=True) is ErrorCode.AUTH_FAILED


def test_403_invalid_key_is_auth_failed() -> None:
    body = '<response status="error" code="403"><result><msg>Invalid key</msg></result></response>'
    assert err(body) is ErrorCode.AUTH_FAILED


def test_other_403_is_permission_denied() -> None:
    body = (
        '<response status="error" code="403"><result><msg>Type [config] not authorized for '
        "user role.</msg></result></response>"
    )
    assert err(body) is ErrorCode.PERMISSION_DENIED


def test_code_7_and_12() -> None:
    assert err('<response status="error" code="7"><msg>No such node</msg></response>') is (
        ErrorCode.NOT_FOUND
    )
    assert err('<response status="error" code="12"><msg>Invalid object</msg></response>') is (
        ErrorCode.INVALID_INPUT
    )


def test_other_error_is_panorama_error() -> None:
    body = '<response status="error" code="17"><msg><line>bad</line></msg></response>'
    assert err(body) is ErrorCode.PANORAMA_ERROR


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (httpx.ConnectError("refused"), ErrorCode.UNREACHABLE),
        (httpx.ReadTimeout("slow"), ErrorCode.TIMEOUT),
        (ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED"), ErrorCode.TLS_ERROR),
        (RuntimeError("x"), ErrorCode.PANORAMA_ERROR),
    ],
)
def test_exceptions(exc: Exception, code: ErrorCode) -> None:
    info = from_exception(exc).info
    assert info.code is code
    assert info.message and info.hint


def test_wrapped_ssl_error_is_tls() -> None:
    try:
        try:
            raise ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED")
        except ssl.SSLError as inner:
            raise httpx.ConnectError("TLS failed") from inner
    except httpx.ConnectError as outer:
        assert from_exception(outer).info.code is ErrorCode.TLS_ERROR
