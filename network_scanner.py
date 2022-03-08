from pydoc import cli
from tabnanny import verbose
import scapy.all as scapy
import optparse

def get_arguments():
    parser=optparse.OptionParser()
    parser.add_option('-i','--ip-address',dest="ip",help="enter the ip address of the target network")
    options,arguments=parser.parse_args()
    if not options.ip:
        print("please specify an ip address........")
        exit(0)
    return options



#creating an ARP Packet
def scan(ip):
    arp_packet=scapy.ARP(pdst=ip) #pdest specifies the ip address of whom we want to find the mac address
    #arp_packet.show()  can be used to see the different fields in the packet to manipulate it if required
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show() again used to find all useful fields of the packet
    arp_broadcast=broadcast/arp_packet #scapy allows for the different  packets to be joined using the / symbol
                    # and note that the packet is now a frame cuz it has a datalink layer wrapping the network layer arp protocol
    answered,unanswered = scapy.srp(arp_broadcast,timeout=1,verbose=False) #timeout is set so that we do not wait on an ip address that does not respond
                                                    # verbose is set to false to remove information that is currently useless to us
                                                    # srp function return two lists of answered and unanswered packets
    # for answer in answered:
    #     print(answer)
    #     print('---------------------------------------') # answered list is a list of pairs containing the original arp message sent and the answered received
    client_list=[]

    for answer in answered:
        client_dict={'ip':answer[1].psrc,'mac':answer[1].hwsrc} #used show function to get to know what fields to call from the packet to desplay it
        client_list.append(client_dict)
    return client_list



def print_scan(client_list):
    print("IP\t\tMAC")
    print('----------------------------------')
    for element in client_list:
        print(element['ip']+"\t"+element["mac"])

    
options=get_arguments()
client_scan=scan(options.ip)
print_scan(client_scan)