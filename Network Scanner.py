import scapy.all as scapy
import socket
import threading

# Function to perform a ping sweep (find active hosts in a network)
def scan_network(ip_range):
    # Sending an ICMP Echo Request to the target IP range
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    active_hosts = []
    for element in answered_list:
        active_hosts.append(element[1].psrc)
    return active_hosts

# Function to scan ports for a given host
def scan_ports(host, port_range):
    open_ports = []
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to scan the network and scan ports for each active host
def scan_network_and_ports(ip_range, port_range):
    active_hosts = scan_network(ip_range)
    print(f"\nActive hosts in the network {ip_range}:")
    
    for host in active_hosts:
        print(f"\nScanning host: {host}")
        open_ports = scan_ports(host, port_range)
        if open_ports:
            print(f"  Open ports on {host}: {', '.join(map(str, open_ports))}")
        else:
            print("  No open ports found.")
    
# Main function to start the network scanning
if __name__ == "__main__":
    # Define the network range and port range
    network_range = "192.168.1.0/24"  # Example: Scan the 192.168.1.0 to 192.168.1.255 network
    ports_to_scan = [22, 80, 443, 8080]  # SSH, HTTP, HTTPS, HTTP-alt ports
    
    print("Starting network scan...")
    scan_network_and_ports(network_range, ports_to_scan)
