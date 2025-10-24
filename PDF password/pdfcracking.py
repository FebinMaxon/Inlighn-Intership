import argparse
import itertools
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pikepdf  # Prerequisite 5 
from tqdm import tqdm  # Prerequisite 7 

def load_passwords(wordlist_file):
    """
    Generator to read passwords from a wordlist file line-by-line.
    Uses File I/O basics (Prerequisite 1)[cite: 11, 14].
    """
    try:
        with open(wordlist_file, "r", encoding="utf-8") as f:
            for line in f:
                yield line.strip()  # [cite: 13, 30]
    except FileNotFoundError:
        print(f"Error: Wordlist file not found at {wordlist_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading wordlist: {e}", file=sys.stderr)
        sys.exit(1)

def generate_passwords(chars, min_length, max_length):
    """
    Generator for on-the-fly password generation using itertools.
    Uses Generators and Itertools (Prerequisite 2)[cite: 34, 37].
    """
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(chars, repeat=length): # [cite: 37, 50]
            yield "".join(combo) # [cite: 36]

def try_password(pdf_file, password):
    """
    Attempts to open the PDF with a given password.
    Uses pikepdf and Exception Handling (Prerequisites 3 & 5)[cite: 56, 104].
    """
    try:
        # Use pikepdf.open() to test the password [cite: 108, 111]
        with pikepdf.open(pdf_file, password=password):
            return password  # Return the password if successful
    except pikepdf._core.PasswordError:
        return None  # Password was incorrect [cite: 59, 62, 109]
    except pikepdf._core.PdfError as e:
        # Handle other PDF-related errors (e.g., corrupted file)
        print(f"\nError processing PDF: {e}", file=sys.stderr)
        return "ERROR" # Signal to stop
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        return "ERROR" # Signal to stop

def get_wordlist_count(wordlist_file):
    """Helper function to count lines in a file for tqdm."""
    try:
        with open(wordlist_file, "r", encoding="utf-8") as f:
            return sum(1 for _ in f)
    except:
        return 0 # Will be handled by load_passwords

def get_generate_count(chars, min_length, max_length):
    """Helper function to calculate total passwords for tqdm."""
    total = 0
    char_count = len(chars)
    for length in range(min_length, max_length + 1):
        total += char_count ** length
    return total

def main():
    """
    Main function to parse arguments and coordinate the cracking process.
    """
    # Prerequisite 4: Command-Line Arguments with argparse [cite: 81, 194]
    parser = argparse.ArgumentParser(description="PDF Cracker Tool",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("pdf_file", help="Path to the password-protected PDF file.")
    
    # Group for mutually exclusive password sources
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("-w", "--wordlist", help="Path to the password wordlist file.")
    source_group.add_argument("-g", "--generate", action="store_true", help="Generate passwords on the fly.")
    
    # Arguments for --generate mode
    gen_group = parser.add_argument_group("Generation Options (use with -g)")
    gen_group.add_argument("--min_length", type=int, default=1, help="Minimum password length (default: 1).")
    gen_group.add_argument("--max_length", type=int, default=4, help="Maximum password length (default: 4). [cite: 202]")
    gen_group.add_argument("--chars", default=string.ascii_letters + string.digits, 
                           help="Character set to use for generation (default: a-zA-Z0-9).")

    args = parser.parse_args()

    # Step 5: Main Execution - Select password source [cite: 196]
    total_passwords = 0
    if args.wordlist:
        print(f"[*] Mode: Wordlist ({args.wordlist})")
        passwords = load_passwords(args.wordlist)
        print("[*] Counting passwords in wordlist...")
        total_passwords = get_wordlist_count(args.wordlist)
        if total_passwords == 0:
            print("Error: Wordlist is empty or could not be read.", file=sys.stderr)
            sys.exit(1)
    else: # args.generate
        print(f"[*] Mode: Generate (Min: {args.min_length}, Max: {args.max_length})")
        print(f"[*] Character set: {args.chars}")
        passwords = generate_passwords(args.chars, args.min_length, args.max_length)
        print("[*] Calculating total password combinations...")
        total_passwords = get_generate_count(args.chars, args.min_length, args.max_length)

    print(f"[*] Total passwords to test: {total_passwords}")
    print(f"[*] Target PDF: {args.pdf_file}")
    
    found_password = None
    
    # Prerequisite 6: Multithreading with concurrent.futures [cite: 128, 192]
    with ThreadPoolExecutor() as executor:
        print("[*] Starting cracker... (Press Ctrl+C to stop)")
        futures = []
        try:
            # Submit all tasks to the thread pool
            for password in passwords:
                futures.append(executor.submit(try_password, args.pdf_file, password)) # [cite: 131]
            
            # Prerequisite 7: Progress Tracking with tqdm [cite: 149, 156]
            for future in tqdm(as_completed(futures), 
                               total=total_passwords, 
                               desc="Cracking", 
                               unit="pass"):
                
                result = future.result() # [cite: 131]
                
                if result == "ERROR":
                    print("A critical error occurred. Stopping all threads.")
                    # Cancel all pending futures
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                if result:
                    found_password = result
                    print(f"\n[+] SUCCESS! Password found: {found_password}")
                    # Cancel all other running/pending tasks
                    executor.shutdown(wait=False, cancel_futures=True)
                    break # Exit the loop
        
        except KeyboardInterrupt:
            print("\n[!] User interrupted. Stopping threads...")
            executor.shutdown(wait=False, cancel_futures=True)
            sys.exit(0)
        except Exception as e:
            print(f"\nAn error occurred during execution: {e}")
            executor.shutdown(wait=False, cancel_futures=True)

    if not found_password:
        print("\n[-] FAILED. Password not found in the provided list or range.")

# Step 5: Main Execution block [cite: 196]
if __name__ == "__main__":
    main()