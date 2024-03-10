import socket
import struct
from datetime import datetime
from threading import Thread

from struct_protocol import *

from sniffer_network.ethernet import Ethernet
from sniffer_network.ipv4 import IPv4
from sniffer_network.icmp import ICMP
from sniffer_network.tcp import TCP
from sniffer_network.udp import UDP
from sniffer_network.pcap import Pcap
from sniffer_network.http import HTTP

from tkinter import ttk
import tkinter as tk

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

root = tk.Tk()
root.title("Sniffer")
root.geometry("600x600")

tk.Label(root, text="Packet Sniffer", font="Helvetica 24 bold").pack(pady=10)

treeview = ttk.Treeview(root)
treeview.column('#0')


def get_ip(data):
    return '.'.join(map(str, data))


def ip_header_packet(data):
    vihl, tos, total_length, identification, flag_offset, ttl, ip_protocol, header_checksum, s_ip, d_ip, s_port, d_port = struct.unpack(
        '!BBHHHBBH4s4sHH', data[:24])

    ip_version = vihl >> 4
    header_length = (vihl & 15)
    x_bit = (flag_offset >> 15) & 1
    DFF = (flag_offset >> 14) & 1
    MFF = (flag_offset >> 13) & 1

    frag_offset = flag_offset & 8191

    return (ip_version, header_length, tos, total_length, identification, x_bit, DFF, MFF,
            frag_offset, ttl, ip_protocol, header_checksum, get_ip(s_ip), get_ip(d_ip), s_port, d_port, data[20:])


dict = {}
no_of_ip = 15
r_no_of_ip = no_of_ip + 10
ddos_file = open("attack_DDoS.txt", 'a')


def uygula():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:

        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        row = treeview.insert('', index=tk.END, text="Ethernet Frame:")
        treeview.insert(row, index=tk.END,
                        text='Destination Mac: {},Source Mac: {},Eth Protocol: {}'.format(eth.dest_mac, eth.src_mac,
                                                                                          eth.proto))
        treeview.pack(expand=True, fill='both')
        # canvas.create_text(300, 50, text="HELLO WORLD", fill="black", font=('Helvetica 15 bold'))

        # IPv4
        if eth.proto == 8:

            (ip_version, header_length, tos, total_length, identification, x_bit, DFF, MFF,
             frag_offset, ttl, ip_protocol, header_checksum, s_ip, d_ip, s_port, d_port, data_ip) = ip_header_packet(
                raw_data)

            t1 = str(datetime.now())
            ddos_file.writelines(t1)
            ddos_file.writelines(" " + s_ip)
            ddos_file.writelines("\n")

            if s_ip not in dict.keys():
                dict[s_ip] = 1
            else:
                dict[s_ip] += 1

            print(dict)

            if dict[s_ip] > no_of_ip:
                line = "DDoS attack is Detected"
                ddos_file.writelines(line)
                ddos_file.writelines(s_ip)
                ddos_file.writelines("\n")

            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
            row1 = treeview.insert('', index=tk.END, text="IPv4 Packet:")
            treeview.insert(row1, index=tk.END,
                            text='Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length,
                                                                                   ipv4.ttl))
            treeview.insert(row1, index=tk.END,
                            text='Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
            # treeview.pack(fill=tk.X)

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))
                row2 = treeview.insert('', index=tk.END, text="ICMP Packet: ")
                treeview.insert(row2, index=tk.END,
                                text='Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                treeview.insert(row2, index=tk.END, text='ICMP Data: '.format(icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                row3 = treeview.insert('', index=tk.END, text="TCP Segment: ")
                treeview.insert(row3, index=tk.END,
                                text='Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                treeview.insert(row3, index=tk.END,
                                text='Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                row4 = treeview.insert(row3, index=tk.END, text="Flags: ")
                treeview.insert(row4, index=tk.END,
                                text='URG: {},\nACK: {},\nPSH: {},\nRST: {},\nSYN: {},\nFIN:{}'.format(tcp.flag_urg,
                                                                                                       tcp.flag_ack,
                                                                                                       tcp.flag_psh,
                                                                                                       tcp.flag_rst,
                                                                                                       tcp.flag_syn,
                                                                                                       tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        row5 = treeview.insert('', index=tk.END, text='HTTP Data: ')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                                treeview.insert(row5, index=tk.END, text='{}'.format(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                            treeview.insert(row5, index=tk.END, text='{}'.format(tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))
                        row6 = treeview.insert('', index=tk.END, text='TCP Data: ')
                        treeview.insert(row6, index=tk.END, text='{}'.format(tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port,
                                                                                         udp.size))
                row7 = treeview.insert('', index=tk.END, text='UDP Segment: ')
                treeview.insert(row7, index=tk.END,
                                text='Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port,
                                                                                                udp.dest_port,
                                                                                                udp.size))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))
                row8 = treeview.insert('', index=tk.END, text='Other IPv4 Data: ')
                treeview.insert(row8, index=tk.END, text='{}'.format(ipv4.data))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))
            row9 = treeview.insert('', index=tk.END, text='Ethernet Data: ')
            treeview.insert(row9, index=tk.END, text='{}'.format(eth.data))

    pcap.close()


thread_value = None
start_value = True


def stop_sniff():
    global start_value
    start_value = True


def threading():
    global thread_value
    if (thread_value is None) or (not thread_value.is_alive()):
        start_value = False
        t1 = Thread(target=uygula)
        t1.start()


btn_frame = tk.Frame(root)
tk.Button(btn_frame, text="Start Sniffing", command=threading,
          font='Helvetica 12 bold').pack(side=tk.LEFT)
tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniff,
          font='Helvetica 12 bold').pack(side=tk.LEFT)
btn_frame.pack()

# run
root.mainloop()

