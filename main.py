import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from args_parser import configure_parser
import time
from scapy.layers.inet import IP, UDP, TCP, ICMP, sr1
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from ipwhois import IPWhois


class Sniffer:
    def __init__(self, args):
        self.ip = args.target
        self.protocol = args.protocol
        if args.port:
            self.port = int(args.port)
        else:
            self.port = args.port
        self.timeout = args.timeout
        self.num = args.num
        self.verbose = args.verbose
        if self.protocol == 'icmp' and self.port:
            print("Wrong args, icmp and port is not compatible")
            sys.exit(1)

    def traceroute(self):
        print(f"Tracing route to {self.ip} over a maximum of {self.num} hops")
        proto_packet = self.get_protocol_packets()
        response = None
        end, start = None, None
        for ttl in range(1, self.num + 1):
            if ':' in self.ip:
                packet = IPv6(dst=self.ip, hlim=ttl) / proto_packet
            else:
                packet = IP(dst=self.ip, ttl=ttl) / proto_packet
            for i in range(3):
                start = time.time()
                response = sr1(packet, timeout=self.timeout, verbose=False)
                end = time.time()
                if response: break
            if not response:
                print(f"{ttl} * {end-start}")
                continue
            auto_sys = ''
            if self.verbose:
                try:
                    auto_sys = IPWhois(response.src).lookup_whois()["asn"]
                except:
                    auto_sys = "Private sys"

            print(f"{ttl} {response.src} {round(end-start, 3)} {auto_sys}")
            if response.haslayer("TCP") or response.code == 3\
                    or response.type == 0 or response.type == 3\
                    or (response.code == 4 and response.type == 1)\
                    or (response.code == 0 and response.type == 129):
                print("Tracing route completed")
                return

    def get_protocol_packets(self):
        if self.protocol == "tcp":
            protocol = TCP(dport=self.port)
        elif self.protocol == "udp":
            protocol = UDP(dport=self.port)
        elif self.protocol == "icmp":
            if ":" in self.ip:
                protocol = ICMPv6EchoRequest()
            else:
                protocol = ICMP()
        else:
            print("Unsupported protocol")
            sys.exit(1)
        return protocol


def main():
    parser = configure_parser()
    args = parser.parse_args()
    sniffer = Sniffer(args)
    sniffer.traceroute()


if __name__ == "__main__":
    main()