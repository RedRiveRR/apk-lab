"""A small DNS client: query encoding, message parsing, UDP with TCP fallback.

The lab does not depend on ``dnspython``. This module speaks just enough of
RFC 1035 for the record types the checks use, and every parser is exercised by
offline fixtures, so a scan never needs a live resolver to be trustworthy.
"""
from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

TYPE_BY_NAME = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48, "TLSA": 52, "CAA": 257,
    "AXFR": 252,
}
NAME_BY_TYPE = {value: key for key, value in TYPE_BY_NAME.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
MAX_MESSAGE = 65535


class DnsError(ValueError):
    """A malformed query answer or a resolver failure."""


def type_code(rtype: str) -> int:
    try:
        return TYPE_BY_NAME[rtype.upper()]
    except KeyError:
        raise DnsError(f"unsupported record type: {rtype}") from None


def encode_name(name: str) -> bytes:
    text = name.rstrip(".")
    payload = b""
    if text:
        for label in text.split("."):
            if not label:
                raise DnsError("a host name cannot contain an empty label")
            try:
                raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
            except UnicodeError as exc:
                raise DnsError(f"the label {label!r} cannot be encoded ({exc})") from None
            if len(raw) > 63:
                raise DnsError(f"the label {label!r} is longer than 63 bytes")
            payload += bytes([len(raw)]) + raw
    if len(payload) > 254:
        raise DnsError("the host name is longer than 255 bytes")
    return payload + b"\x00"


def build_query(name: str, rtype: str = "A", qid: Optional[int] = None) -> Tuple[int, bytes]:
    identifier = qid if qid is not None else random.randrange(0, 65536)
    header = struct.pack(">HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
    body = encode_name(name) + struct.pack(">HH", type_code(rtype), 1)
    return identifier, header + body


def _read_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    labels: List[str] = []
    total = 0
    jumped = False
    next_offset = offset
    while True:
        if offset >= len(data):
            raise DnsError("the message ends inside a name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("a compression pointer is truncated")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            jumped = True
            if depth >= 32:
                raise DnsError("a compression pointer loops")
            suffix, _ = _read_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            break
        if length & 0xC0:
            raise DnsError("an unsupported label type")
        offset += 1
        label = data[offset:offset + length]
        if len(label) != length:
            raise DnsError("a label is truncated")
        total += length + 1
        if total > 254:
            raise DnsError("the name is longer than 255 bytes")
        labels.append(label.decode("ascii", "replace"))
        offset += length
        if not jumped:
            next_offset = offset
    return ".".join(labels), next_offset


def _rdata(rtype: int, data: bytes, offset: int, length: int) -> object:
    chunk = data[offset:offset + length]
    if len(chunk) != length:
        raise DnsError("the record data is truncated")
    if rtype == 1 and length == 4:
        return socket.inet_ntoa(chunk)
    if rtype == 28 and length == 16:
        return socket.inet_ntop(socket.AF_INET6, chunk)
    if rtype in (2, 5, 12):
        return _read_name(data, offset)[0]
    if rtype == 15 and length >= 3:
        preference = struct.unpack(">H", chunk[:2])[0]
        return {"preference": preference, "exchange": _read_name(data, offset + 2)[0]}
    if rtype == 16:
        parts: List[str] = []
        cursor = 0
        while cursor < length:
            size = chunk[cursor]
            cursor += 1
            parts.append(chunk[cursor:cursor + size].decode("utf-8", "replace"))
            cursor += size
        return " ".join(parts)
    if rtype == 6:
        mname, cursor = _read_name(data, offset)
        rname, cursor = _read_name(data, cursor)
        if cursor + 20 > offset + length:
            raise DnsError("the SOA record is truncated")
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[cursor:cursor + 20])
        return {"mname": mname, "rname": rname, "serial": serial, "refresh": refresh,
                "retry": retry, "expire": expire, "minimum": minimum}
    if rtype == 33 and length >= 7:
        priority, weight, port = struct.unpack(">HHH", chunk[:6])
        return {"priority": priority, "weight": weight, "port": port,
                "target": _read_name(data, offset + 6)[0]}
    if rtype == 43 and length >= 5:
        key_tag, algorithm, digest_type = struct.unpack(">HBB", chunk[:4])
        return {"key_tag": key_tag, "algorithm": algorithm, "digest_type": digest_type,
                "digest": chunk[4:].hex()}
    if rtype == 257 and length >= 2:
        tag_len = chunk[1]
        return {"flags": chunk[0], "tag": chunk[2:2 + tag_len].decode("ascii", "replace"),
                "value": chunk[2 + tag_len:].decode("utf-8", "replace")}
    return chunk.hex()


def parse_message(data: bytes) -> Dict[str, object]:
    if len(data) < 12:
        raise DnsError("a DNS message is at least 12 bytes")
    identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise DnsError("the question is truncated")
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4
        questions.append({"name": name, "type": NAME_BY_TYPE.get(qtype, str(qtype)), "class": qclass})
    sections: Dict[str, List[Dict[str, object]]] = {"answers": [], "authority": [], "additional": []}
    for key, count in (("answers", ancount), ("authority", nscount), ("additional", arcount)):
        for _ in range(count):
            name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                raise DnsError("a resource record header is truncated")
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            value = _rdata(rtype, data, offset, rdlength)
            offset += rdlength
            sections[key].append({
                "name": name,
                "type": NAME_BY_TYPE.get(rtype, str(rtype)),
                "class": rclass,
                "ttl": ttl,
                "value": value,
            })
    return {
        "id": identifier,
        "flags": flags,
        "truncated": bool(flags & 0x0200),
        "rcode": flags & 0x000F,
        "questions": questions,
        **sections,
    }


def _system_servers() -> List[str]:
    configured = os.environ.get("WEBSEC_DNS_SERVERS")
    if configured:
        servers = [part.strip() for part in configured.split(",") if part.strip()]
        if servers:
            return servers
    servers = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers or ["1.1.1.1", "9.9.9.9"]


class Resolver:
    """A bounded DNS resolver over UDP with a TCP fallback for truncated answers."""

    def __init__(self, servers: Optional[Sequence[str]] = None, timeout: float = 3.0,
                 attempts: int = 2):
        self.servers = list(servers or _system_servers())
        self.timeout = max(0.5, float(timeout))
        self.attempts = max(1, int(attempts))

    def _udp(self, packet: bytes, server: str) -> bytes:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
        return data

    def _tcp(self, packet: bytes, server: str) -> bytes:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(self.timeout, 3.0))
            sock.connect((server, 53))
            sock.sendall(struct.pack(">H", len(packet)) + packet)
            header = _recv_exact(sock, 2)
            size = struct.unpack(">H", header)[0]
            if size > MAX_MESSAGE:
                raise DnsError("the TCP answer claims more than 64 KiB")
            return _recv_exact(sock, size)

    def query(self, name: str, rtype: str = "A") -> Dict[str, object]:
        identifier, packet = build_query(name, rtype)
        errors = []
        for server in self.servers:
            for attempt in range(self.attempts):
                try:
                    data = self._udp(packet, server)
                    message = parse_message(data)
                    if message["id"] != identifier:
                        raise DnsError("the answer id does not match the query")
                    if message["truncated"]:
                        message = parse_message(self._tcp(packet, server))
                    if message["rcode"] != 0:
                        raise DnsError(f"{RCODES.get(message['rcode'], message['rcode'])} from {server}")
                    return message
                except (OSError, DnsError) as exc:
                    errors.append(f"{server}: {exc}")
                    if attempt + 1 < self.attempts:
                        continue
        raise DnsError("; ".join(errors[:4]) or "no DNS server answered")

    def values(self, name: str, rtype: str = "A") -> List[object]:
        message = self.query(name, rtype)
        wanted = type_code(rtype)
        return [record["value"] for record in message["answers"]
                if TYPE_BY_NAME.get(record["type"]) == wanted]

    def resolve(self, name: str) -> List[str]:
        try:
            return [str(ipaddress.ip_address(name))]
        except ValueError:
            pass
        addresses: List[str] = []
        for rtype in ("A", "AAAA"):
            try:
                for value in self.values(name, rtype):
                    if isinstance(value, str) and value not in addresses:
                        addresses.append(value)
            except DnsError:
                continue
        return addresses

    def cname_chain(self, name: str, limit: int = 8) -> List[str]:
        chain = []
        current = name
        for _ in range(limit):
            try:
                targets = self.values(current, "CNAME")
            except DnsError:
                break
            if not targets:
                break
            target = str(targets[0]).rstrip(".")
            if target in chain or target == current:
                break
            chain.append(target)
            current = target
        return chain

    def reverse(self, address: str) -> str:
        parsed = ipaddress.ip_address(address)
        name = parsed.reverse_pointer
        try:
            values = self.values(name, "PTR")
        except DnsError:
            return ""
        return str(values[0]).rstrip(".") if values else ""

    def axfr(self, server: str, zone: str, timeout: float = 6.0) -> Dict[str, object]:
        """One AXFR request to one name server. Only an audit of an owned zone."""
        _, packet = build_query(zone, "AXFR")
        try:
            data = self._tcp_query(server, packet, timeout)
            message = parse_message(data)
            return {"server": server, "rcode": message["rcode"],
                    "records": len(message["answers"]), "error": ""}
        except (OSError, DnsError) as exc:
            return {"server": server, "rcode": None, "records": 0, "error": str(exc)}

    def _tcp_query(self, server: str, packet: bytes, timeout: float) -> bytes:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(timeout, 3.0))
            sock.connect((server, 53))
            sock.sendall(struct.pack(">H", len(packet)) + packet)
            header = _recv_exact(sock, 2)
            size = struct.unpack(">H", header)[0]
            if size > MAX_MESSAGE:
                raise DnsError("the TCP answer claims more than 64 KiB")
            return _recv_exact(sock, size)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise DnsError("the TCP connection closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
