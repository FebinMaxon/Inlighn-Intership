#!/usr/bin/env python3

"""
Port Scanner
Based on the Inlighn Tech "Prerequisites for the Port Scanner Project" document.

This script scans a target host for open ports, identifies services,
and attempts to grab service banners, all using standard Python libraries.
"""

import socket
import concurrent.futures
import sys
import time

# Prerequisite 5: ANSI Colors for formatted output
# (May not work on very old Windows CMD)
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    GRAY = '\033[90m'

# Prerequisite 2 & 3: Function to grab the banner
def get_banner(s):
    """
    Attempts to receive a 1024-byte banner from an open port.
    Handles timeouts and decoding errors.
    """
    try:
        banner = s.recv(1024).decode('utf-8', 'ignore').strip()
        return banner
    except socket.timeout:
        return "Timeout"
    except Exception:
        return "" # Return empty string on other errors

# Prerequisite 1, 2, 3: The main scanning function for each thread
def scan_port(target_ip, port):
    """
    Tries to connect to a single port. If open, it gets the service
    name and banner. Returns a result dictionary or None.
    """
    try:
        # Create a new socket for each thread
        # Prerequisite 2: AF_INET (IPv4), SOCK_STREAM (TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a short timeout (0.5s) so threads don't hang long
        s.settimeout(0.5)
        
        # Prerequisite 1: Use connect_ex()
        # It returns 0 if the connection is successful (port is open)
        if s.connect_ex((target_ip, port)) == 0:
            service = "Unknown"
            try:
                # Prerequisite 2: Get service name from port number
                service = socket.getservbyport(port, "tcp")
            except (OSError, socket.error):
                pass # If service isn't in the local list, just keep "Unknown"

            # Prerequisite 2: Grab the banner
            banner = get_banner(s)
            
            s.close()
            
            # Return all found info
            return {
                "port": port,
                "service": service,
                "banner": banner
            }
            
    except (socket.timeout, socket.error):
        pass # Handle connection timeouts or errors
    except Exception as e:
        pass # Catch any other unexpected errors
    finally:
        s.close()
        
    return None # Port is closed or an error occurred

# Prerequisite 4, 5, 6: Main function to run the scan
def main_scan(target_host, start_port, end_port):
    """
    Orchestrates the port scan, including hostname resolution,
    thread pooling, and printing the final results.
    """
    
    print(f"[*] Resolving hostname: {target_host}")
    target_ip = ""
    try:
        # Prerequisite 2: Resolve hostname to IP
        target_ip = socket.gethostbyname(target_host)
        print(f"[*] Target IP: {target_ip}")
    except socket.gaierror:
        print(f"Error: Hostname '{target_host}' could not be resolved.")
        return

    print(f"[*] Scanning ports {start_port}-{end_port} on {target_host}...")
    
    open_ports_found = []
    total_ports = (end_port - start_port) + 1
    processed_count = 0
    start_time = time.time()

    # Prerequisite 4: Multithreading with ThreadPoolExecutor
    # Use 100 threads (max_workers) for a fast scan
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        
        # Submit all ports to be scanned
        futures = {executor.submit(scan_port, target_ip, port): port for port in range(start_port, end_port + 1)}

        # Process results as they are completed
        for future in concurrent.futures.as_completed(futures):
            processed_count += 1
            result = future.result()
            
            if result:
                open_ports_found.append(result)

            # Prerequisite 6: Progress Tracking with sys.stdout
            # This overwrites the same line in the console
            percent_done = (processed_count / total_ports) * 100
            sys.stdout.write(f"\r[*] Progress: {processed_count}/{total_ports} ports ({percent_done:.1f}%)")
            sys.stdout.flush()

    end_time = time.time()
    
    # Move to a new line after the progress bar is done
    print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds.")

    if not open_ports_found:
        print("[*] No open ports found.")
        return

    # Prerequisite 5: Format and print the final results
    print(f"\n[+] Open ports on {target_host}:")
    
    # Sort results by port number
    open_ports_found.sort(key=lambda x: x['port'])
    
    # Print table header
    print(f"\n{Colors.GREEN}{'PORT':<8} {'SERVICE':<15} {Colors.YELLOW}BANNER{Colors.RESET}")
    print("-" * 50)
    
    for res in open_ports_found:
        port = f"{Colors.GREEN}{res['port']:<8}{Colors.RESET}"
        service = f"{res['service']:<15}"
        # Truncate long banners for cleaner output
        banner = f"{Colors.YELLOW}{res['banner'][:60]}...{Colors.RESET}" if len(res['banner']) > 60 else f"{Colors.YELLOW}{res['banner']}{Colors.RESET}"
        print(f"{port} {service} {banner}")

# Prerequisite 6: Entry point of the script
if __name__ == "__main__":
    try:
        target = input("Enter target host (e.g., 127.0.0.1 or scanme.nmap.org): ").strip()
        port_range_str = input("Enter port range (e.g., 1-100 or 80-1000): ").strip()
        
        start, end = map(int, port_range_str.split('-'))
        
        if start < 0 or end > 65535 or start > end:
            print("Error: Invalid port range. Must be between 0 and 65535.")
        else:
            main_scan(target, start, end)
            
    except ValueError:
        print("Error: Invalid input. Please check your target and port range format.")
    except KeyboardInterrupt:
        print("\n[*] Scan aborted by user.")
        sys.exit()