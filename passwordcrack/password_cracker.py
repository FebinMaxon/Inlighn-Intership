import argparse
import hashlib
import itertools
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from tqdm import tqdm # Prerequisite 6
except ImportError:
    print("Error: 'tqdm' module not found. Please install it with 'pip install tqdm'")
    sys.exit(1)

def generate_passwords(chars, min_length, max_length):
    """
    Generator for on-the-fly password combinations using itertools.
    (Prerequisite 3)
    """
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)

def check_hash(password, target_hash, hash_function):
    """
    Hashes a password and compares it to the target hash.
    Returns the password if it matches, otherwise None.
    (Prerequisite 1)
    """
    try:
        # Hash the password. It must be encoded to bytes.
        hashed_password = hash_function(password.encode('utf-8')).hexdigest()
        
        # Compare
        if hashed_password == target_hash:
            return password
    except Exception:
        pass # Ignore errors (e.g., encoding issues)
    return None

def main():
    """
    Main function to parse arguments and run the cracking process.
    """
    
    # Prerequisite 4: Command-Line Arguments with argparse
    parser = argparse.ArgumentParser(description="Password Cracker Tool",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("hash", help="The target hash to crack.")
    
    # Group for mutually exclusive password sources
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-w", "--wordlist", help="Path to the password wordlist file.")
    mode_group.add_argument("-g", "--generate", action="store_true", 
                            help="Generate passwords on the fly (brute-force).")

    # Options for hash type
    parser.add_argument("-t", "--type", default="md5", 
                        help="Hash type (e.g., md5, sha1, sha256, sha512). Default: md5")
    
    # Prerequisite 7: Options for generation
    gen_group = parser.add_argument_group("Generation Options (use with -g)")
    gen_group.add_argument("--min_length", type=int, default=1, 
                           help="Minimum password length (default: 1).")
    gen_group.add_argument("--max_length", type=int, default=4, 
                           help="Maximum password length (default: 4).")
    gen_group.add_argument("--chars", default=string.ascii_lowercase + string.digits, 
                           help="Character set for generation (default: a-z + 0-9).")
    
    args = parser.parse_args()
    
    # --- Step 1: Setup ---
    try:
        # Get the hashing function from hashlib (e.g., hashlib.md5)
        hash_fn = getattr(hashlib, args.type)
    except AttributeError:
        print(f"Error: Invalid hash type '{args.type}'.")
        print(f"Supported types include: md5, sha1, sha256, sha512, etc.")
        sys.exit(1)

    passwords_iterator = None
    total_passwords = 0
    
    if args.wordlist:
        # --- Wordlist Mode (Prerequisite 2) ---
        print(f"[*] Mode: Wordlist ({args.wordlist})")
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                # Read all lines and strip whitespace
                passwords_list = [line.strip() for line in f]
            total_passwords = len(passwords_list)
            passwords_iterator = iter(passwords_list) # Use an iterator
            if total_passwords == 0:
                print("Error: Wordlist is empty or could not be read.")
                sys.exit(1)
        except FileNotFoundError:
            print(f"Error: Wordlist file not found at {args.wordlist}")
            sys.exit(1)
            
    else: 
        # --- Generate Mode (Prerequisite 3 & 7) ---
        print(f"[*] Mode: Generate (Brute-force)")
        print(f"[*] Character Set: {args.chars}")
        print(f"[*] Length Range: {args.min_length} to {args.max_length}")
        
        passwords_iterator = generate_passwords(args.chars, args.min_length, args.max_length)
        
        # Calculate total for tqdm
        try:
            print("[*] Calculating total password combinations...")
            total_passwords = 0
            for length in range(args.min_length, args.max_length + 1):
                total_passwords += len(args.chars) ** length
        except OverflowError:
            print("[!] Warning: Total combinations are too large to calculate. Progress bar will not show a total.")
            total_passwords = 0 # Tqdm will run without a total
    
    print(f"[*] Target Hash ({args.type}): {args.hash}")
    if total_passwords > 0:
        print(f"[*] Total Passwords to Test: {total_passwords}")
    
    # --- Step 3 & 5: Cracking and Multithreading ---
    found_password = None
    print("[*] Starting cracker... (Press Ctrl+C to stop)")
    start_time = time.time()

    # Use max 100 workers, or fewer if not needed
    max_w = 100 
    
    with ThreadPoolExecutor(max_workers=max_w) as executor:
        # Prerequisite 6: Setup tqdm progress bar
        with tqdm(total=total_passwords, desc="Cracking", unit="pass", mininterval=0.5) as pbar:
            
            # Submit tasks to the thread pool
            futures = {executor.submit(check_hash, p, args.hash, hash_fn): p for p in passwords_iterator}
            
            try:
                # Process results as they are completed
                for future in as_completed(futures):
                    pbar.update(1) # Update progress for each completed hash
                    result = future.result()
                    
                    if result:
                        found_password = result
                        end_time = time.time()
                        # Clear the progress bar line
                        sys.stdout.write("\r" + " " * pbar.ncols + "\r") 
                        pbar.close() # Close the progress bar
                        
                        print(f"\n[+] SUCCESS! Password found.")
                        print(f"[*] Password: {found_password}")
                        print(f"[*] Hash: {args.hash}")
                        print(f"[*] Time taken: {end_time - start_time:.2f} seconds")
                        
                        # Stop all other threads
                        executor.shutdown(wait=False, cancel_futures=True)
                        break # Exit the loop
            
            except KeyboardInterrupt:
                print("\n[!] User interrupted. Stopping threads...")
                pbar.close()
                executor.shutdown(wait=False, cancel_futures=True)
                sys.exit(0)

    if not found_password:
        end_time = time.time()
        print(f"\n[-] FAILED. Password not found in the wordlist or range.")
        print(f"[*] Time taken: {end_time - start_time:.2f} seconds")

# --- Step 5: Main Execution ---
if __name__ == "__main__":
    main()