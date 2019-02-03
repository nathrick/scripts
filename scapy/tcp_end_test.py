from scapy.all import *
import os
import sys
import thread
import time

euid = os.geteuid()
if euid != 0:
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    os.execlpe('sudo', *args)

log_file = 'tcp_end_connect_test.pcap'
os.remove(log_file) if os.path.isfile(log_file) else None


def pkt_callback(pkt):
    print pkt.summary()
    wrpcap(log_file, pkt, append=True)


def start_capturing():
    sniff(iface="enp0s8", filter='tcp', prn=pkt_callback)


def run_test():
    sport = 33333
    eth = Ether(src='08:00:26:2d:67:32', dst='00:23:b0:4d:6d:22')
    ipv6 = IPv6(src='fd53:7cb8:383:3::11', dst='fd53:7cb8:383:3::79')

    SYN = TCP(sport=sport, dport=13400, flags='S',
              seq=1000)
    SYNACK = srp1(eth / ipv6 / SYN, iface="enp0s8")

    ACK = TCP(sport=sport, dport=13400, flags='A', seq=SYNACK.ack,
              ack=SYNACK.seq + 1)
    sendp(eth / ipv6 / ACK, iface="enp0s8")

    time.sleep(5)

    FIN = TCP(sport=sport, dport=13400, flags='FA', seq=SYNACK.ack,
              ack=SYNACK.seq + 1)
    FINACK = srp1(eth / ipv6 / FIN, iface="enp0s8")

    LASTACK = TCP(sport=sport, dport=13400, flags='A',
                  seq=FINACK.ack, ack=FINACK.seq + 1)
    sendp(eth / ipv6 / LASTACK, iface="enp0s8")


print "Adding rule to iptables..."
os.system('ip6tables -F OUTPUT')
os.system('ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
os.system('ip6tables -L OUTPUT')

thread.start_new_thread(start_capturing, ())

time.sleep(5)

print ""
print "TCP end connection test started..."
run_test()
print "TCP end connection test finished..."
