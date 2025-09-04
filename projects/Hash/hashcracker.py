#!/usr/bin/env python3
import hashlib
import os
import itertools
import threading
from colorama import Fore, Style, init
from tqdm import tqdm
import zlib
import crcmod
from Crypto.Hash import MD2, MD4, RIPEMD
from tabulate import tabulate
import time

init(autoreset=True)

# === Hash Type Detector ===
def detect_hash_type(hash_str):
    length = len(hash_str)
    if length == 32:
        return 'md5'
    elif length == 40:
        return 'sha1'
    elif length == 64:
        return 'sha256'
    elif length == 128:
        return 'sha512'
    elif length == 32 and hash_str.isupper():
        return 'ntlm'
    elif length == 32 and MD2:
        return 'md2'
    elif length == 32 and MD4:
        return 'md4'
    elif length == 64 and RIPEMD:
        return 'ripemd-160'
    elif length == 66 and RIPEMD:
        return 'ripemd-256'
    elif length == 80 and RIPEMD:
        return 'ripemd-320'
    elif length == 56 and hasattr(hashlib, "sha3_224"):
        return 'sha3-224'
    elif length == 64 and hasattr(hashlib, "sha3_256"):
        return 'sha3-256'
    elif length == 96 and hasattr(hashlib, "sha3_384"):
        return 'sha3-384'
    elif length == 128 and hasattr(hashlib, "sha3_512"):
        return 'sha3-512'
    return None

# === Hash Generator ===
def hash_word(word, hash_type):
    word = word.strip()
    try:
        if hash_type == 'md2':
            return MD2.new(word.encode()).hexdigest()
        elif hash_type == 'md4':
            return MD4.new(word.encode()).hexdigest()
        elif hash_type == 'md5':
            return hashlib.md5(word.encode()).hexdigest()
        elif hash_type == 'ntlm':
            return hashlib.new('md4', word.encode('utf-16le')).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(word.encode()).hexdigest()
        elif hash_type == 'sha224':
            return hashlib.sha224(word.encode()).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(word.encode()).hexdigest()
        elif hash_type == 'sha384':
            return hashlib.sha384(word.encode()).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(word.encode()).hexdigest()
        elif hash_type == 'sha3-224':
            return hashlib.sha3_224(word.encode()).hexdigest()
        elif hash_type == 'sha3-256':
            return hashlib.sha3_256(word.encode()).hexdigest()
        elif hash_type == 'sha3-384':
            return hashlib.sha3_384(word.encode()).hexdigest()
        elif hash_type == 'sha3-512':
            return hashlib.sha3_512(word.encode()).hexdigest()
        elif hash_type == 'ripemd-128':
            return RIPEMD.new(word.encode(), digest_bits=128).hexdigest()
        elif hash_type == 'ripemd-160':
            return RIPEMD.new(word.encode(), digest_bits=160).hexdigest()
        elif hash_type == 'ripemd-256':
            return RIPEMD.new(word.encode(), digest_bits=256).hexdigest()
        elif hash_type == 'ripemd-320':
            return RIPEMD.new(word.encode(), digest_bits=320).hexdigest()
        elif hash_type == 'crc16':
            return hex(crcmod.predefined.mkCrcFun('crc-ccitt-false')(word.encode()))[2:]
        elif hash_type == 'crc32':
            return format(zlib.crc32(word.encode()) & 0xFFFFFFFF, '08x')
        elif hash_type == 'adler32':
            return format(zlib.adler32(word.encode()) & 0xFFFFFFFF, '08x')
    except Exception as e:
        print(Fore.RED + f"[!] Error hashing '{word}': {e}")
        return None
    return None

# === Dictionary Attack ===
def dictionary_attack(target_hash, wordlist_path, hash_type):
    result = [None]

    def worker(words):
        for word in tqdm(words, desc=Fore.CYAN + "Trying", unit="word", leave=False):
            if hash_word(word, hash_type) == target_hash:
                result[0] = word.strip()
                break

    try:
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            words = f.readlines()
        mid = len(words) // 2
        t1 = threading.Thread(target=worker, args=(words[:mid],))
        t2 = threading.Thread(target=worker, args=(words[mid:],))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except FileNotFoundError:
        print(Fore.RED + "[!] Wordlist not found.")
    return result[0]

# === Brute-force Attack ===
def brute_force_attack(target_hash, charset, max_length, hash_type):
    print(Fore.YELLOW + f"[*] Starting brute-force up to length {max_length}...")
    for length in range(1, max_length + 1):
        combos = itertools.product(charset, repeat=length)
        for combo in tqdm(combos, desc=f"Length {length}", unit="try", leave=False):
            candidate = ''.join(combo)
            if hash_word(candidate, hash_type) == target_hash:
                return candidate
    return None

# === Online Lookup Stub ===
def online_lookup_stub(hash_str):
    print(Fore.CYAN + f"[*] Online lookup not implemented for: {hash_str}")
    return None

# === Single Hash Mode ===
def crack_single_hash():
    target_hash = input(Fore.MAGENTA + "Enter hash: ").strip()
    hash_type = detect_hash_type(target_hash)
    if not hash_type:
        print(Fore.RED + "[!] Could not detect hash type.")
        return
    print(Fore.CYAN + f"[*] Detected hash type: {hash_type}")
    wordlist_path = input(Fore.MAGENTA + "Enter wordlist path: ").strip()

    print(Fore.YELLOW + "[*] Dictionary attack started...")
    result = dictionary_attack(target_hash, wordlist_path, hash_type)

    if result:
        print(Fore.GREEN + f"[✓] Password found: {result}")
    else:
        print(Fore.RED + "[-] Not found in wordlist.")
        choice = input("Try brute-force? (y), online lookup (o), exit (n): ").strip().lower()
        if choice == 'y':
            charset = input("Enter charset (e.g. abc123): ")
            max_length = int(input("Max password length: "))
            result = brute_force_attack(target_hash, charset, max_length, hash_type)
            if result:
                print(Fore.GREEN + f"[✓] Password cracked: {result}")
            else:
                print(Fore.RED + "[-] Brute-force failed.")
        elif choice == 'o':
            online_lookup_stub(target_hash)

# === Multi-hash Mode ===
def crack_hashes_from_file():
    hash_file = input(Fore.MAGENTA + "Enter hash file path: ").strip()
    wordlist_path = input(Fore.MAGENTA + "Enter wordlist path: ").strip()

    if not os.path.exists(hash_file):
        print(Fore.RED + "[!] Hash file not found.")
        return

    cracked_hashes = []
    print(Fore.CYAN + "[*] Multi-hash cracking started...\n")
    with open(hash_file, 'r') as f:
        hashes = [line.strip() for line in f if line.strip()]

    for h in hashes:
        hash_type = detect_hash_type(h)
        if not hash_type:
            print(Fore.RED + f"[!] Unknown format: {h}")
            continue

        print(Fore.YELLOW + f"[*] Cracking {h} (type: {hash_type})...")
        result = dictionary_attack(h, wordlist_path, hash_type)
        if result:
            cracked_hashes.append([h, result, hash_type])
        else:
            cracked_hashes.append([h, "Not found", hash_type])

    # Print results in table
    print("\n" + Fore.GREEN + tabulate(cracked_hashes, headers=["Hash", "Password", "Type"], tablefmt="fancy_grid"))

# === Main Menu ===
def main():
    print(Fore.MAGENTA + "\n=== Ultimate Hash Cracker ===")
    print(Fore.CYAN + "1. Crack a single hash")
    print(Fore.CYAN + "2. Crack multiple hashes from file")
    choice = input(Fore.MAGENTA + "Choose mode (1 or 2): ").strip()
    if choice == '1':
        crack_single_hash()
    elif choice == '2':
        crack_hashes_from_file()
    else:
        print(Fore.RED + "[!] Invalid choice.")

if __name__ == "__main__":
    main()
