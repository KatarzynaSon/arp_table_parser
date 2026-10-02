"""Core parsing logic for ARP table output.

Two input formats are supported:

1. ``arp -n`` style output (Linux ``net-tools``)::

    Address                  HWtype  HWaddress           Flags Mask          Iface
    192.168.1.1              ether   00:11:22:33:44:55   C                     eth0
    192.168.1.2              ether   00:11:22:33:44:56   C                     eth0

2. The contents of ``/proc/net/arp``::

    IP address       HW type     Flags       HW address            Mask     Device
    192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0

The two formats are structurally similar (columnar, header on the first
line) but differ in the HW-type vocabulary (``ether`` vs ``0x1``) and in
the presence of a ``Flags`` column whose value differs
(``C`` vs ``0x2``). Rather than try to unify them with a fragile
detector, we expose one function per format. The caller knows where the
text came from.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class ArpEntry:
    """A single resolved ARP-table row.

    ``hw_type`` and ``flags`` are kept as the raw strings the table
    contained (``"ether"`` / ``"0x1"``, ``"C"`` / ``"0x2"``). Normalising
    them to an enum would lose information the caller might want, and the
    two formats use different vocabularies that a single enum cannot
    honestly span.
    """

    ip_address: str
    hw_type: str
    hw_address: str
    flags: str
    interface: str


def _split_fields(line: str) -> List[str]:
    """Split a columnar line on runs of whitespace, dropping empties.

    ``str.split()`` with no argument already does this and ignores leading
    and trailing whitespace. We wrap it only so tests can pin the
    behaviour (collapsing internal runs of spaces/tabs into one break).
    """
    return line.split()


def _looks_like_header(line: str) -> bool:
    """Heuristically detect the header row so we can skip it.

    The header is the one row whose first field is not an IP address.
    Detecting "not an IP" is more robust than matching a fixed header
    string: locales and ``arp`` versions rename the columns (``Address``
vs ``Adresse``, ``Iface`` vs ``Device``), but the header never holds a
valid IPv4 dotted quad.
    """
    first = line.split()[0] if line.split() else ""
    return not _is_ipv4(first)


def _is_ipv4(token: str) -> bool:
    """Strict IPv4 dotted-quad check.

    Rejects anything with non-octet characters or out-of-range octets.
    Used both to skip headers and to reject garbage leading fields
    (e.g. an empty mask ``*`` that has shifted a column).
    """
    parts = token.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        # Reject leading zeros only for length > 1, so a literal "0" is fine.
        if len(part) > 1 and part.startswith("0"):
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True


def _normalise_hw_address(addr: str) -> str:
    """Lowercase and lightly validate a MAC.

    Real ARP output uses lowercase colon-separated hex. We lowercase
defensively in case the surrounding tool upper-cased it, and we accept
the incomplete entry marker ``<incomplete>`` verbatim — there is no
honest value to synthesise for it.
    """
    if addr in ("<incomplete>", "<incomplete>"):
        return addr.lower()
    if _is_mac(addr):
        return addr.lower()
    return addr


def _is_mac(token: str) -> bool:
    """Accept aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff only.

    Keeping this strict means we reject column-misaligned rows where a
    missing HW address has let the next column slide left.
    """
    sep = ":" if ":" in token else ("-" if "-" in token else None)
    if sep is None:
        return False
    parts = token.split(sep)
    if len(parts) != 6:
        return False
    for part in parts:
        if len(part) != 2:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    return True


def parse_arp_output(text: str) -> List[ArpEntry]:
    """Parse ``arp -n`` style output.

    Accepts the ``net-tools`` columnar layout. The HWtype column is
    optional in some locales (a row may read ``192.168.1.5 (foo) ether …``);
    we handle the common case of five whitespace-separated fields per row
    and skip any row that does not have a parseable IP and MAC. That skips
    lines with parenthesised hostnames as well as the header.

    We do NOT attempt to support the BSD ``arp -an`` format
    (``? (10.0.0.1) at xx:xx:xx:xx:xx:xx on en0 expires in 119s``) — the
    README states this scope. Supporting it would mean a second parser
    sharing no logic with this one.
    """
    entries: List[ArpEntry] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = _split_fields(line)
        if len(fields) < 5:
            continue
        # We expect exactly: IP HWtype HWaddr Flags Iface. We do not
        # trust the header word to tell us column order — we verify by
        # content. This protects against locales that reorder columns.
        ip, hw_type, hw_addr, flags, iface = fields[0], fields[1], fields[2], fields[3], fields[4]
        if not _is_ipv4(ip):
            continue
        if not _is_mac(hw_addr):
            continue
        entries.append(
            ArpEntry(
                ip_address=ip,
                hw_type=hw_type,
                hw_address=_normalise_hw_address(hw_addr),
                flags=flags,
                interface=iface,
            )
        )
    return entries


def parse_proc_net_arp(text: str) -> List[ArpEntry]:
    """Parse the contents of ``/proc/net/arp``.

    The file is six columns: IP, HW type, Flags, HW address, Mask, Device.
    The Mask column is almost always ``*`` and carries no real
    information; we drop it from the returned record (there is no field
    for it on :class:`ArpEntry`). Rows with an incomplete HW address
    (the literal string ``<incomplete>``) are kept; their ``hw_address``
    is preserved verbatim so the caller can filter them out if desired.
    """
    entries: List[ArpEntry] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if _looks_like_header(line):
            continue
        fields = _split_fields(line)
        if len(fields) < 6:
            continue
        ip, hw_type, flags, hw_addr, _mask, iface = (
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
        )
        if not _is_ipv4(ip):
            continue
        entries.append(
            ArpEntry(
                ip_address=ip,
                hw_type=hw_type,
                hw_address=_normalise_hw_address(hw_addr),
                flags=flags,
                interface=iface,
            )
        )
    return entries


def parse_arp_file(path: str) -> List[ArpEntry]:
    """Parse ``/proc/net/arp`` directly from disk.

    Convenience wrapper around :func:`parse_proc_net_arp`. We read the
    file rather than exec ``arp`` so the function works in containers
    with no ``arp`` binary and no CAP_NET_ADMIN. The path is taken
    verbatim; the caller decides whether it really is
    ``/proc/net/arp`` or a saved copy.
    """
    with open(os.fsencode(path), "rb") as fh:
        data = fh.read()
    return parse_proc_net_arp(data.decode("utf-8"))
