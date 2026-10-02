"""ARP Table Parser.

Parses the output of the Unix ``arp`` command and Linux ``/proc/net/arp``
into a list of structured records. Zero third-party dependencies.

The library is intentionally small: it knows how to parse the two common
Linux formats and nothing else. Non-parseable lines are ignored rather
than raising — an ARP dump from a busy router routinely contains entries
in transitional states that no parser can represent, and failing on them
would make the library useless for its actual job of summarising a table.
"""

from .core import (
    ArpEntry,
    parse_arp_output,
    parse_proc_net_arp,
    parse_arp_file,
)

__all__ = [
    "ArpEntry",
    "parse_arp_output",
    "parse_proc_net_arp",
    "parse_arp_file",
]

__version__ = "1.0.0"
