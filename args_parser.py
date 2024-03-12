import argparse


def configure_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog = "scanner",
        description = "port_scanner")
    parser.add_argument("-t", type=float, default=2,
                        help="Timeout for response in seconds (default: 2)", dest="timeout")
    parser.add_argument("-p", type=int, help="Port for udp or tcp", dest="port")
    parser.add_argument("-n", type=int, default=25, help="Max amount of requests", dest="num")
    parser.add_argument("-v" , action="store_true",
                        help="Output of the autonomous system number for each ip address", dest="verbose")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument('protocol', choices = ['tcp', 'udp', 'icmp'],
                        help = 'Protocol type')
    return parser
