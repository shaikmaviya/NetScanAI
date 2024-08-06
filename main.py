from scapy.all import ARP, Ether, srp
import ipaddress
import socket
import nmap
import argparse

def scan_ipaddresses(network):
    # Create an ARP request packet to identify active devices
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive responses
    try:
        result = srp(packet, timeout=10, verbose=False)[0]
    except PermissionError as e:
        print(f"Permission error: {e}. Please run the script with elevated privileges.")
        return []
    except Exception as e:
        print(f"Error during scanning: {e}")
        return []

    # Process the responses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def scan_vulnerabilities(ip):
    # Create an nmap port scanner object
    nm = nmap.PortScanner()

    # Scan the IP address for vulnerabilities using nmap scripting engine
    try:
        print(f"Scanning {ip} for vulnerabilities...")
        nm.scan(ip, arguments='--script vuln')

        # Parse the scan results
        scan_data = nm[ip]
        vulnerabilities = []

        if 'tcp' in scan_data:
            for port in scan_data['tcp']:
                if 'script' in scan_data['tcp'][port]:
                    for script, output in scan_data['tcp'][port]['script'].items():
                        vulnerabilities.append({
                            'port': port,
                            'script': script,
                            'output': output
                        })

        return vulnerabilities

    except nmap.PortScannerError as e:
        print(f"nmap error: {e}")
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []

def scan_ports(ip):
    # List of important ports (common service ports)
    important_ports = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 514, 587, 631, 636, 873, 993, 995, 1080, 1433, 1434, 1723, 2049, 3306, 3389, 5060, 5061, 5432, 5900, 6379, 8080, 8443, 8888]   
    open_ports = []

    for port in important_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set timeout to 1 second
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            else :
                print(f"Port {port} is not open")
    return open_ports


def main():
    while True:
        print("\nMenu:")
        print("1. Scan IP addresses on a local network")
        print("2. Scan ports on a specific IP address") 
        print("3. Scan IP address for vulnerabilities")# want to add 
        print("4. Exit")

        choice = input("Enter your choice: ")
        
        if choice == '1':
            # Define the network to scan (e.g., "192.168.1.0/24")
            network = input("Enter the network range (e.g., 192.168.1.0/24): ")
            
            # Validate the network input
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError:
                print("Invalid network range. Please use CIDR notation, e.g., 192.168.1.0/24.")
                continue

            print("Scanning network...")
            devices = scan_ipaddresses(network)
            
            if devices:
                print("Active devices found:")
                for index, device in enumerate(devices, start=1):
                    print(f"{index}. IP Address: {device['ip']}, MAC Address: {device['mac']}")
            else:
                print("No devices found.")
        
        elif choice == '2':
            ip = input("Enter the IP address to scan (e.g., 192.168.1.1): ")
            
            # Validate the IP address
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print("Invalid IP address. Please enter a valid IP address.")
                continue

            print("Scanning ports...")
            open_ports = scan_ports(ip)
            
            if open_ports:
                print("Open ports found:")
                for port in open_ports:
                    print(f"Port {port} is open.")
            else:
                print("No open ports found.")

        elif choice == '3':
            ip = input("Enter the IP address to scan (e.g., 192.168.1.1): ")

            # Validate the IP address
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print("Invalid IP address. Please enter a valid IP address.")
                continue

            vulnerabilities = scan_vulnerabilities(ip)

            if vulnerabilities:
                print(f"Vulnerabilities found on {ip}:")
                for vuln in vulnerabilities:
                    print(f"Port: {vuln['port']}, Script: {vuln['script']}, Output: {vuln['output']}")
            else:
                print(f"No vulnerabilities found on {ip}.")
        
        elif choice == '3':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please select a valid option.")

# def main():
#     parser = argparse.ArgumentParser(description="Network scanning tool")

#     parser.add_argument('-m', '--mode', choices=['scan_network', 'scan_ports', 'scan_vulns'], required=True, help="Mode of operation")
#     parser.add_argument('-n', '--network', type=str, help="Network range in CIDR notation (e.g., 192.168.1.0/24)")
#     parser.add_argument('-i', '--ip', type=str, help="IP address to scan")

#     args = parser.parse_args()

#     if args.mode == 'scan_network':
#         if not args.network:
#             parser.error("Network range is required for 'scan_network' mode.")
        
#         try:
#             ipaddress.ip_network(args.network, strict=False)
#         except ValueError:
#             print("Invalid network range. Please use CIDR notation, e.g., 192.168.1.0/24.")
#             return

#         print("Scanning network...")
#         devices = scan_ipaddresses(args.network)
        
#         if devices:
#             print("Active devices found:")
#             for index, device in enumerate(devices, start=1):
#                 print(f"{index}. IP Address: {device['ip']}, MAC Address: {device['mac']}")
#         else:
#             print("No devices found.")

#     elif args.mode == 'scan_ports':
#         if not args.ip:
#             parser.error("IP address is required for 'scan_ports' mode.")
        
#         try:
#             ipaddress.ip_address(args.ip)
#         except ValueError:
#             print("Invalid IP address. Please enter a valid IP address.")
#             return

#         print("Scanning ports...")
#         open_ports = scan_ports(args.ip)
        
#         if open_ports:
#             print("Open ports found:")
#             for port in open_ports:
#                 print(f"Port {port} is open.")
#         else:
#             print("No open ports found.")

#     elif args.mode == 'scan_vulns':
#         if not args.ip:
#             parser.error("IP address is required for 'scan_vulns' mode.")
        
#         try:
#             ipaddress.ip_address(args.ip)
#         except ValueError:
#             print("Invalid IP address. Please enter a valid IP address.")
#             return

#         vulnerabilities = scan_vulnerabilities(args.ip)

#         if vulnerabilities:
#             print(f"Vulnerabilities found on {args.ip}:")
#             for vuln in vulnerabilities:
#                 print(f"Port: {vuln['port']}, Script: {vuln['script']}, Output: {vuln['output']}")
#         else:
#             print(f"No vulnerabilities found on {args.ip}.")


if __name__ == "__main__":
    main()
