import os
import tempfile
import unittest

from arp_table_parser import (
    ArpEntry,
    parse_arp_output,
    parse_proc_net_arp,
    parse_arp_file,
)


class TestArpOutput(unittest.TestCase):
    def test_parses_typical_rows(self):
        text = (
            "Address                  HWtype  HWaddress           Flags Mask          Iface\n"
            "192.168.1.1              ether   00:11:22:33:44:55   C                     eth0\n"
            "192.168.1.2              ether   00:11:22:33:44:56   C                     eth0\n"
        )
        entries = parse_arp_output(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0], ArpEntry("192.168.1.1", "ether", "00:11:22:33:44:55", "C", "eth0"))
        self.assertEqual(entries[1], ArpEntry("192.168.1.2", "ether", "00:11:22:33:44:56", "C", "eth0"))

    def test_skips_header_without_matching_words(self):
        # Localised header words should still be skipped because the first
        # field is not a valid IPv4 address.
        text = (
            "Adresse Typ Adresse Matériel Indicateurs Masque Interface\n"
            "10.0.0.1 ether 00:1a:2b:3c:4d:5e C eth0\n"
        )
        entries = parse_arp_output(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].ip_address, "10.0.0.1")

    def test_lowercases_mac(self):
        text = "192.168.0.5 ether AA:BB:CC:DD:EE:FF C wlan0\n"
        entries = parse_arp_output(text)
        self.assertEqual(entries[0].hw_address, "aa:bb:cc:dd:ee:ff")

    def test_accepts_dash_separated_mac(self):
        text = "172.16.0.9 ether 00-1a-2b-3c-4d-5e C eth1\n"
        entries = parse_arp_output(text)
        self.assertEqual(entries[0].hw_address, "00-1a-2b-3c-4d-5e")

    def test_ignores_blank_and_short_lines(self):
        text = "\n192.168.1.1\n192.168.1.2 ether 00:11:22:33:44:55 C eth0\n"
        entries = parse_arp_output(text)
        self.assertEqual(len(entries), 1)

    def test_rejects_invalid_ip(self):
        text = "not-an-ip ether 00:11:22:33:44:55 C eth0\n"
        entries = parse_arp_output(text)
        self.assertEqual(entries, [])

    def test_rejects_invalid_mac(self):
        text = "192.168.1.1 ether not-a-mac C eth0\n"
        entries = parse_arp_output(text)
        self.assertEqual(entries, [])

    def test_empty_input(self):
        self.assertEqual(parse_arp_output(""), [])


class TestProcNetArp(unittest.TestCase):
    def test_parses_typical_rows(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n"
            "10.0.0.1         0x1         0x2         00:1a:2b:3c:4d:5e     *        eth1\n"
        )
        entries = parse_proc_net_arp(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(
            entries[0],
            ArpEntry("192.168.1.1", "0x1", "00:11:22:33:44:55", "0x2", "eth0"),
        )

    def test_keeps_incomplete_entries(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.99     0x1         0x0         <incomplete>          *        eth0\n"
        )
        entries = parse_proc_net_arp(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].hw_address, "<incomplete>")

    def test_skips_header(self):
        text = "IP address HW type Flags HW address Mask Device\n"
        self.assertEqual(parse_proc_net_arp(text), [])

    def test_rejects_short_row(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         00:11:22:33:44:55\n"
        )
        self.assertEqual(parse_proc_net_arp(text), [])

    def test_empty_input(self):
        self.assertEqual(parse_proc_net_arp(""), [])


class TestParseArpFile(unittest.TestCase):
    def test_reads_file_from_disk(self):
        content = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".arp", delete=False, encoding="utf-8") as fh:
            fh.write(content)
            path = fh.name
        try:
            entries = parse_arp_file(path)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].ip_address, "192.168.1.1")
            self.assertEqual(entries[0].interface, "eth0")
        finally:
            os.unlink(path)


class TestArpEntryImmutability(unittest.TestCase):
    def test_entry_is_frozen(self):
        entry = ArpEntry("1.2.3.4", "ether", "00:11:22:33:44:55", "C", "eth0")
        with self.assertRaises(Exception):
            entry.ip_address = "5.6.7.8"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
