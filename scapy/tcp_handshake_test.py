from scapy.all import *
import os

euid = os.geteuid()
if euid != 0:
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    os.execlpe('sudo', *args)

log_file = 'tcp_handshake_test.pcap'
os.remove(log_file) if os.path.isfile(log_file) else None


def pkt_callback(pkt):
    print pkt.summary()
    wrpcap(log_file, pkt, append=True)
    if IPv6 in pkt and TCP in pkt:
        if pkt[IPv6].dst == 'fd53:7cb8:383:5::76' and pkt[TCP].dport == 29184:
            if pkt[TCP].flags == 'S':
                eth = Ether(src='08:00:26:2d:67:32', dst='00:23:b0:4d:6d:22')
                ipv6 = IPv6(src='fd53:7cb8:383:5::76',
                            dst='fd53:7cb8:383:3::79')
                SYNACK = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='SA', seq=pkt[TCP].ack,
                             ack=pkt[TCP].seq + 1)
                ACK = srp1(eth / ipv6 / SYNACK, iface="enp0s8")


def stopfilter(pkt):
    return (pkt[IPv6].dst == 'fd53:7cb8:383:5::76' and pkt[TCP].dport == 29184 and pkt[TCP].flags == 'A')


def run_test():
    sniff(iface="enp0s8", filter='ip6 and tcp',
          stop_filter=stopfilter, prn=pkt_callback)


print "Adding rule to iptables..."
os.system('ip6tables -F OUTPUT')
os.system(
    'ip6tables -A OUTPUT -p icmpv6 --icmpv6-type destination-unreachable -j DROP')
os.system('ip6tables -L OUTPUT')


print ""
print "TCP handshake simulation test started..."
run_test()
print ""
print "TCP handshake simulation test finished..."
