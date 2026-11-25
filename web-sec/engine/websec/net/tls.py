"""TLS inspection: handshake details and a minimal DER certificate reader.

``ssl`` gives the protocol and cipher; the certificate's names and validity come
from a small ASN.1 walk here, because ``getpeercert()`` returns an empty mapping
when verification is off — which is exactly the case a posture scanner needs.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ..scope import ScopeRefused

OID_COMMON_NAME = "2.5.4.3"
OID_ORG = "2.5.4.10"
OID_SAN = "2.5.29.17"
_STRING_TAGS = {0x0C: "utf-8", 0x13: "ascii", 0x16: "ascii", 0x14: "latin-1", 0x1A: "ascii"}
_MAX_DEPTH = 16


class CertError(ValueError):
    """A certificate that could not be parsed."""


class Tlv:
    __slots__ = ("tag", "start", "end")

    def __init__(self, tag: int, start: int, end: int):
        self.tag = tag
        self.start = start
        self.end = end

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Tlv(tag=0x{self.tag:02x}, {self.start}:{self.end})"


def _tlv(data: bytes, offset: int) -> Tlv:
    if offset + 2 > len(data):
        raise CertError("the DER value is truncated")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise CertError("multi-byte tags are not supported")
    first = data[offset + 1]
    cursor = offset + 2
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise CertError("the DER length is malformed")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    else:
        length = first
    end = cursor + length
    if end > len(data):
        raise CertError("the DER value runs past the buffer")
    return Tlv(tag, cursor, end)


def _children(data: bytes, start: int, end: int) -> List[Tlv]:
    items = []
    cursor = start
    while cursor < end:
        item = _tlv(data, cursor)
        if item.end > end:
            raise CertError("a DER child runs past its parent")
        items.append(item)
        cursor = item.end
    if cursor != end:
        raise CertError("trailing bytes inside a DER value")
    return items


def _der_oid(data: bytes, item: Tlv) -> str:
    if item.end <= item.start:
        return ""
    first = data[item.start]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[item.start + 1:item.end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _string(data: bytes, item: Tlv) -> str:
    if item.tag == 0x1E:
        return data[item.start:item.end].decode("utf-16-be", "replace")
    encoding = _STRING_TAGS.get(item.tag)
    if encoding:
        return data[item.start:item.end].decode(encoding, "replace")
    if item.tag == 0x06:
        return _der_oid(data, item)
    return ""


def _name(data: bytes, item: Tlv) -> str:
    try:
        parts = []
        for rdn in _children(data, item.start, item.end):
            for pair in _children(data, rdn.start, rdn.end):
                values = _children(data, pair.start, pair.end)
                if len(values) >= 2:
                    key = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.6": "C",
                           "2.5.4.8": "ST", "2.5.4.7": "L"}.get(
                               _der_oid(data, values[0]), _der_oid(data, values[0]))
                    value = _string(data, values[-1])
                    if value:
                        parts.append(f"{key}={value}")
        return ", ".join(parts)
    except CertError:
        return ""


def _time(data: bytes, item: Tlv) -> str:
    raw = data[item.start:item.end].decode("ascii", "replace").strip()
    text = raw[:-1] if raw.endswith("Z") else raw
    for pattern, width in (("%y%m%d%H%M%S", 12), ("%Y%m%d%H%M%S", 14),
                           ("%y%m%d%H%M", 10), ("%Y%m%d%H%M", 12)):
        if len(text) == width:
            try:
                parsed = datetime.strptime(text, pattern)
            except ValueError:
                continue
            if pattern.startswith("%y"):
                year = parsed.year
                parsed = parsed.replace(year=year + (2000 if year < 1970 else 0))
            return parsed.replace(tzinfo=timezone.utc).isoformat()
    return ""


def _extensions(data: bytes, item: Tlv) -> Dict[str, Tuple[bool, Tlv]]:
    found: Dict[str, Tuple[bool, Tlv]] = {}
    for extension in _children(data, item.start, item.end):
        fields = _children(data, extension.start, extension.end)
        if len(fields) < 2 or fields[0].tag != 0x06:
            continue
        oid = _der_oid(data, fields[0])
        critical = fields[1].tag == 0x01
        payload = fields[2] if critical and len(fields) > 2 else fields[1]
        if payload.tag == 0x04:
            found[oid] = (critical, payload)
    return found


def parse_certificate(der: bytes) -> Dict[str, object]:
    """Names, SANs, validity and a fingerprint from a DER certificate."""
    outer = _tlv(der, 0)
    if outer.tag != 0x30:
        raise CertError("the certificate is not a SEQUENCE")
    parts = _children(der, outer.start, outer.end)
    if not parts or parts[0].tag != 0x30:
        raise CertError("the certificate has no tbsCertificate")
    fields = _children(der, parts[0].start, parts[0].end)
    index = 1 if fields and fields[0].tag == 0xA0 else 0
    if len(fields) < index + 6:
        raise CertError("the tbsCertificate is too short")
    serial_item = fields[index]
    issuer_item = fields[index + 2]
    validity_item = fields[index + 3]
    subject_item = fields[index + 4]
    extensions: Dict[str, Tuple[bool, Tlv]] = {}
    for extra in fields[index + 6:]:
        if extra.tag == 0xA3:
            inner = _children(der, extra.start, extra.end)
            if inner:
                extensions = _extensions(der, inner[0])
    times = _children(der, validity_item.start, validity_item.end)
    not_before = _time(der, times[0]) if len(times) > 0 else ""
    not_after = _time(der, times[1]) if len(times) > 1 else ""
    sans: List[str] = []
    if OID_SAN in extensions:
        _, payload = extensions[OID_SAN]
        try:
            names = _tlv(der, payload.start)
            for entry in _children(der, names.start, names.end):
                if entry.tag == 0x82:      # dNSName
                    sans.append(der[entry.start:entry.end].decode("ascii", "replace"))
                elif entry.tag == 0x87:    # iPAddress
                    raw = der[entry.start:entry.end]
                    if len(raw) == 4:
                        sans.append(socket.inet_ntoa(raw))
                    elif len(raw) == 16:
                        sans.append(socket.inet_ntop(socket.AF_INET6, raw))
        except CertError:
            pass
    return {
        "serial": format(int.from_bytes(der[serial_item.start:serial_item.end], "big"), "x")[:64],
        "issuer": _name(der, issuer_item),
        "subject": _name(der, subject_item),
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans[:200],
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
    }


@dataclass
class TlsInfo:
    host: str
    port: int = 443
    protocol: str = ""
    cipher: str = ""
    bits: int = 0
    not_before: str = ""
    not_after: str = ""
    days_left: Optional[int] = None
    sans: List[str] = field(default_factory=list)
    issuer: str = ""
    subject: str = ""
    serial: str = ""
    fingerprint: str = ""
    verified: Optional[bool] = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.protocol)

    def as_dict(self) -> Dict[str, object]:
        return {
            "host": self.host, "port": self.port, "protocol": self.protocol,
            "cipher": self.cipher, "bits": self.bits, "not_before": self.not_before,
            "not_after": self.not_after, "days_left": self.days_left,
            "sans": self.sans[:50], "issuer": self.issuer, "subject": self.subject,
            "serial": self.serial, "fingerprint_sha256": self.fingerprint,
            "verified": self.verified, "error": self.error,
        }


def _context(verify: bool, minimum=None, maximum=None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    try:
        if minimum is not None:
            context.minimum_version = minimum
        if maximum is not None:
            context.maximum_version = maximum
    except (ValueError, ssl.SSLError):
        pass
    return context


def probe(host: str, port: int = 443, guard=None, timeout: float = 6.0,
          verify: bool = False) -> TlsInfo:
    info = TlsInfo(host=host, port=port)
    if guard is not None:
        try:
            guard.require("host", host)
        except ScopeRefused as exc:
            info.error = f"scope refused: {exc.reason}"
            return info
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with _context(verify).wrap_socket(raw, server_hostname=host) as tls:
                info.protocol = tls.version() or ""
                cipher = tls.cipher()
                if cipher:
                    info.cipher, info.bits = cipher[0], int(cipher[2] or 0)
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError) as exc:
        info.error = str(getattr(exc, "reason", exc))
        return info
    if der:
        try:
            parsed = parse_certificate(der)
        except CertError as exc:
            info.error = f"certificate parse failed: {exc}"
            return info
        info.not_before = str(parsed["not_before"])
        info.not_after = str(parsed["not_after"])
        info.sans = list(parsed["sans"])
        info.issuer = str(parsed["issuer"])
        info.subject = str(parsed["subject"])
        info.serial = str(parsed["serial"])
        info.fingerprint = str(parsed["fingerprint_sha256"])
        if info.not_after:
            try:
                expiry = datetime.fromisoformat(info.not_after)
                info.days_left = int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400)
            except ValueError:
                info.days_left = None
    return info


def probe_versions(host: str, port: int = 443, guard=None, timeout: float = 4.0,
                   versions: Optional[List[Tuple[str, object]]] = None) -> List[Dict[str, object]]:
    """Which protocol versions the endpoint accepts. A local OpenSSL refusal is reported."""
    if guard is not None:
        try:
            guard.require("host", host)
        except ScopeRefused as exc:
            return [{"version": "all", "supported": False, "error": f"scope refused: {exc.reason}"}]
    checks = versions or [(name, getattr(ssl.TLSVersion, name, None)) for name in
                          ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3")]
    results = []
    for name, version in checks:
        if version is None:
            results.append({"version": name, "supported": False, "error": "not available in this Python"})
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with _context(False, minimum=version, maximum=version).wrap_socket(
                        raw, server_hostname=host) as tls:
                    results.append({"version": name, "supported": True, "negotiated": tls.version() or name,
                                    "error": ""})
        except (OSError, ssl.SSLError) as exc:
            results.append({"version": name, "supported": False, "error": str(getattr(exc, "reason", exc))})
    return results
