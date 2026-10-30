import argparse, unittest
from mirage.cli import parse_ports

class PortArgumentTests(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(parse_ports("80,443,8000-8002"),[80,443,8000,8001,8002])
    def test_invalid(self):
        for value in ("0","65536","90-80","1-5000","abc",""):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError): parse_ports(value)

if __name__=="__main__": unittest.main()
