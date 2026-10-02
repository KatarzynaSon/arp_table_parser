# ARP Table Parser

A small, dependency-free Python library for parsing the output of the Linux `arp -n` command and the contents of `/proc/net/arp` into a list of `ArpEntry` records.

```python
from arp_table_parser import parse_arp_output, parse_proc_net_arp, parse_arp_file, ArpEntry

# From the `arp -n` command
entries = parse_arp_output("""Address                  HWtype  HWaddress           Flags Mask          Iface
192.168.1.1              ether   00:11:22:33:44:55   C                     eth0
""")
print(entries[0].ip_address, entries[0].hw_address, entries[0].interface)

# From /proc/net/arp on disk
for e in parse_arp_file("/proc/net/arp"):
    print(e.ip_address, e.interface)
```

The exported names are:

- `ArpEntry` — a frozen dataclass with fields `ip_address`, `hw_type`, `hw_address`, `flags`, `interface`.
- `parse_arp_output(text)` — parse `arp -n` style output.
- `parse_proc_net_arp(text)` — parse the text contents of `/proc/net/arp`.
- `parse_arp_file(path)` — read a file (typically `/proc/net/arp`) and parse it.

## Why this exists

Inspecting the ARP table from Python usually means either shelling out to `arp` and regexing the result, or reading `/proc/net/arp` and splitting on whitespace. Both work, but the handling of incomplete entries, localised headers, and MAC case is easy to get wrong in one-off scripts. This library does that handling once, in one place, with no dependencies.

The trade-off: the library supports exactly two input formats and nothing else. BSD `arp -an` output (`? (10.0.0.1) at xx:xx:xx:xx:xx:xx on en0 expires in 119s`) is not supported. If you need that, this is the wrong library.

## The awkward edge

`/proc/net/arp` can contain rows whose HW address is the literal string `<incomplete>` — the neighbour was known but its link-layer address has not been resolved. This library keeps those rows verbatim in `hw_address` rather than dropping them, because whether they are interesting is the caller's call. Check for `<incomplete>` in `hw_address` if you want only resolved neighbours.

The `arp -n` parser verifies each row by content (valid IPv4 in the first field, valid MAC in the third) rather than by matching header words. Localised `arp` output renames the header columns; the header is still skipped because its first field is not a valid IP. This means a genuinely garbled data row is also silently skipped — if you need to know about unparseable rows, count them yourself by comparing the input line count to `len(parse_arp_output(text))`.
