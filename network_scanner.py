#!/user/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP Range")
    (options, arguments) = parser.parse_args()
    return options

def scan(ip):
#    this is the easy way =>  scapy.arping(ip)

    arp_request = scapy.ARP(pdst=ip)
#    print(arp_request.show())
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#   print(broadcast.show())
    arp_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    # print(arp_broadcast.show())
    # print(answered_list.summary())


    clients_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dict)
        # print(element[1].psrc + "\t\t" + element[1].hwsrc)
        # print("--------------------------------------------------------------------------------")
    return clients_list

def print_result(results_list):
    print("--------------------------------------------------------------------------------")
    print("IP\t\t\tMAC Address\n--------------------------------------------------------------------------------")
    for client in results_list:
        print(client["IP"] + "\t\t" + client["MAC"])
        print("--------------------------------------------------------------------------------")

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

#  source /home/kawekaweau/Hacking/python_ethical_hacking_from_scratch/mac_changer/venv/bin/activate