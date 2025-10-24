import scapy.all as scapy  # Prerequisite 1 & 6
import ipaddress           # Prerequisite 2
import threading           # Prerequisite 5
from queue import Queue    # Prerequisite 5
import socket              # Prerequisite 4 & 7
import sys
import time

# A thread-safe queue to store the results
result_queue = Queue() # Prerequisite 5

def scan(ip):
    """
    Sends an ARP request to a single IP address and tries to resolve its hostname.
    Puts the result in the global result_queue.
    """
    try:
        # Prerequisite 1 & 6: Create ARP request and Ethernet broadcast packet
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Send packet and receive response. srp() = Send and Receive Packets
        # timeout=1 means it will wait 1 second for a reply
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        # If we get a reply, the host is up
        if answered_list:
            client_mac = answered_list[0][1].hwsrc  # MAC address
            client_ip = answered_list[0][1].psrc   # IP address
            hostname = "Unknown"
            
            try:
                # Prerequisite 4 & 7: Resolve hostname from IP
                hostname = socket.gethostbyaddr(client_ip)[0]
            except socket.herror:
                # Could not resolve hostname
                pass
            
            # Add the found device to the queue
            result_queue.put({"ip": client_ip, "mac": client_mac, "hostname": hostname})

    except Exception as e:
        # Handle potential errors, e.g., if scapy fails
        print(f"Error scanning {ip}: {e}", file=sys.stderr)

def print_results(results):
    """
    Formats and prints the discovered devices in a clean table.
    """
    print("\nScan Complete. Found {} devices:\n".format(len(results)))
    print("IP Address\t\tMAC Address\t\tHostname")
    print("-------------------------------------------------------------------------")
    for client in results:
        print(f"{client['ip']:<16}\t{client['mac']:<17}\t{client['hostname']}")

def worker(q):
    """Worker function for threads. Pulls an IP from the queue and scans it."""
    while not q.empty():
        try:
            ip = q.get_nowait()
            scan(str(ip))
        except:
            break

def main():
    """
    Main function to parse input, set up threads, and run the scan.
    """
    # 5. Entry Point: Prompt user for CIDR
    cidr_input = input("Enter the network to scan (e.g., 192.168.1.0/24): ").strip()

    try:
        # Prerequisite 2: Parse CIDR and get all host IPs
        network = ipaddress.ip_network(cidr_input, strict=False)
        all_hosts = list(network.hosts())
        print(f"[*] Scanning {len(all_hosts)} hosts on {cidr_input}...")
    except ValueError:
        print(f"Error: Invalid CIDR notation '{cidr_input}'. Exiting.", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    
    # Create a queue and fill it with all hosts to scan
    scan_queue = Queue()
    for host in all_hosts:
        scan_queue.put(host)

    # 4. Main Function: Spawn threads
    threads = []
    # Use 100 threads, or fewer if there are not many hosts
    thread_count = min(100, len(all_hosts))
    
    for _ in range(thread_count):
        # Create a thread that will run the 'worker' function
        t = threading.Thread(target=worker, args=(scan_queue,))
        t.start()
        threads.append(t)

    # Wait for all threads to complete their work
    for t in threads:
        t.join()

    # Collect all results from the thread-safe queue
    discovered_clients = []
    while not result_queue.empty():
        discovered_clients.append(result_queue.get())

    end_time = time.time()

    # 3. Print Results
    print_results(discovered_clients)
    print(f"\nScan finished in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()