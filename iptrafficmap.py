import geoip2.database
import sys
import dpkt
import pcap
import datetime
import socket
import stun

DB_PATH = ""
COUNTRY_DB = "GeoLite2-Country.mmdb"
CITY_DB = "GeoLite2-City.mmdb"

verbose = False

def mac_addr(mac_string):
    """Print out MAC address given a string

    Args:
        mac_string: the string representation of a MAC address
    Returns:
        printable MAC address
    """
    return ':'.join('%02x' % b for b in mac_string)

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address: the string representation of a MAC address
    Returns:
        printable IP address
    """
    try:
        ss = socket.inet_ntop(socket.AF_INET, address)
    except:
        ss = socket.inet_ntoa(address)
    return ss
    
def sniff_packet():
    devices = pcap.findalldevs()

    # Ask user to enter device name to sniff
    print("Available devices are :")
    count = 0
    for d in devices:
        print(str(count)+".", d, ip_to_str(pcap.lookupnet(d)[0]))
        count += 1

    dev = input("Enter device name to sniff : ")
    print("Sniffing: " + devices[int(dev)])
    
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap.pcap(name=devices[int(dev)]):
        if verbose:
            # Print out the timestamp in UTC
            print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf)
        if verbose:
            print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            if verbose:
                print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.offset & dpkt.ip.IP_DF)
        more_fragments = bool(ip.offset & dpkt.ip.IP_MF)
        fragment_offset = ip.offset & dpkt.ip.IP_OFFMASK

        # Print out the info
        try:
            success = find_ip(ip_to_str(ip.dst))
            if success:
                print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
                    (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
        except geoip2.errors.AddressNotFoundError:
            if verbose:
                print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
                    (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

def find_ip(ipaddr):
    # Replace "city" with the method corresponding to the database
    # that you are using, e.g., "country".
    response = reader.city(ipaddr)
    if response.city.name:
        print("\t" + response.city.name)
        print("\t" + response.subdivisions[0].names["en"])
        print("\t" + response.country.names["en"])
        # print("")
        return True
    else:
        return False
    
if __name__ == "__main__":
    
    if len(sys.argv) == 2:
        print("Parsing IP: " + sys.argv[1])
        ipaddr = sys.argv[1]
    else:
        extIP = stun.get_ip_info()
        print(extIP)
        print("External IP: " + extIP[1])
        ipaddr = extIP[1]

    # This creates a Reader object. You should use the same object
    # across multiple requests as creation of it is expensive.
    reader = geoip2.database.Reader(DB_PATH + CITY_DB)

    find_ip(ipaddr)
        
    sniff_packet()
    
    
