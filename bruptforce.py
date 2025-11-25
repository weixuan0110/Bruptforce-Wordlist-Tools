#!/usr/bin/env python3
"""
BruteForce CLI Tool
A comprehensive brute force tool for hash cracking and decoding
Supports MD5, SHA1, SHA256, Base64, and more
"""

import argparse
import hashlib
import base64
import itertools
import string
import sys
import os
import time
from typing import List, Optional, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class BruteForcer:
    """Main brute force class with various attack methods"""
    
    def __init__(self):
        self.found = False
        self.result = None
        self.lock = threading.Lock()
        self.attempts = 0
        
    def md5_hash(self, text: str) -> str:
        """Generate MD5 hash of text"""
        return hashlib.md5(text.encode()).hexdigest()
    
    def sha1_hash(self, text: str) -> str:
        """Generate SHA1 hash of text"""
        return hashlib.sha1(text.encode()).hexdigest()
    
    def sha256_hash(self, text: str) -> str:
        """Generate SHA256 hash of text"""
        return hashlib.sha256(text.encode()).hexdigest()
    
    def sha512_hash(self, text: str) -> str:
        """Generate SHA512 hash of text"""
        return hashlib.sha512(text.encode()).hexdigest()
    
    def base64_encode(self, text: str) -> str:
        """Encode text to base64"""
        return base64.b64encode(text.encode()).decode()
    
    def base64_decode(self, encoded: str) -> Optional[str]:
        """Decode base64 string"""
        try:
            return base64.b64decode(encoded).decode()
        except:
            return None
    
    def generate_wordlist(self, min_len: int, max_len: int, charset: str) -> Generator[str, None, None]:
        """Generate all possible combinations for brute force"""
        for length in range(min_len, max_len + 1):
            for combination in itertools.product(charset, repeat=length):
                yield ''.join(combination)
    
    def load_wordlist_file(self, filepath: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Wordlist file '{filepath}' not found")
            return []
    
    def hash_attack(self, target_hash: str, wordlist: List[str], hash_type: str, max_workers: int = 4):
        """Perform hash attack using wordlist"""
        hash_functions = {
            'md5': self.md5_hash,
            'sha1': self.sha1_hash,
            'sha256': self.sha256_hash,
            'sha512': self.sha512_hash
        }
        
        if hash_type not in hash_functions:
            print(f"Unsupported hash type: {hash_type}")
            return None
        
        hash_func = hash_functions[hash_type]
        target_hash = target_hash.lower().strip()
        
        print(f"Starting {hash_type.upper()} attack...")
        print(f"Target hash: {target_hash}")
        print(f"Wordlist size: {len(wordlist)}")
        print(f"Using {max_workers} threads")
        print("-" * 50)
        
        def check_password(word):
            with self.lock:
                if self.found:
                    return None
                self.attempts += 1
                if self.attempts % 1000 == 0:
                    print(f"Attempts: {self.attempts:,}")
            
            computed_hash = hash_func(word)
            if computed_hash == target_hash:
                with self.lock:
                    if not self.found:
                        self.found = True
                        self.result = word
                        print(f"\n[SUCCESS] Password found: {word}")
                        print(f"Hash: {computed_hash}")
                        print(f"Attempts: {self.attempts:,}")
                return word
            return None
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_password, word) for word in wordlist]
            
            for future in as_completed(futures):
                if self.found:
                    # Cancel remaining tasks
                    for f in futures:
                        f.cancel()
                    break
        
        end_time = time.time()
        
        if self.found:
            print(f"Time elapsed: {end_time - start_time:.2f} seconds")
            return self.result
        else:
            print(f"\n[FAILED] Password not found after {self.attempts:,} attempts")
            print(f"Time elapsed: {end_time - start_time:.2f} seconds")
            return None
    
    def base64_attack(self, target_encoded: str, wordlist: List[str]):
        """Perform base64 attack"""
        print(f"Starting Base64 attack...")
        print(f"Target encoded: {target_encoded}")
        print(f"Wordlist size: {len(wordlist)}")
        print("-" * 50)
        
        start_time = time.time()
        
        for i, word in enumerate(wordlist):
            if i % 1000 == 0 and i > 0:
                print(f"Attempts: {i:,}")
            
            encoded = self.base64_encode(word)
            if encoded == target_encoded:
                print(f"\n[SUCCESS] Original text found: {word}")
                print(f"Base64: {encoded}")
                print(f"Attempts: {i + 1:,}")
                print(f"Time elapsed: {time.time() - start_time:.2f} seconds")
                return word
        
        print(f"\n[FAILED] Original text not found after {len(wordlist):,} attempts")
        print(f"Time elapsed: {time.time() - start_time:.2f} seconds")
        return None
    
    def brute_force_attack(self, target: str, attack_type: str, min_len: int = 1, 
                          max_len: int = 6, charset: str = None, max_workers: int = 4):
        """Perform brute force attack with generated wordlist"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"Starting brute force attack...")
        print(f"Target: {target}")
        print(f"Attack type: {attack_type}")
        print(f"Length range: {min_len}-{max_len}")
        print(f"Charset: {charset}")
        print(f"Using {max_workers} threads")
        print("-" * 50)
        
        start_time = time.time()
        
        def check_combination(combination):
            with self.lock:
                if self.found:
                    return None
                self.attempts += 1
                if self.attempts % 10000 == 0:
                    print(f"Attempts: {self.attempts:,} | Current: {combination}")
            
            if attack_type == 'base64':
                encoded = self.base64_encode(combination)
                if encoded == target:
                    with self.lock:
                        if not self.found:
                            self.found = True
                            self.result = combination
                            print(f"\n[SUCCESS] Original text found: {combination}")
                    return combination
            else:
                hash_functions = {
                    'md5': self.md5_hash,
                    'sha1': self.sha1_hash,
                    'sha256': self.sha256_hash,
                    'sha512': self.sha512_hash
                }
                
                if attack_type in hash_functions:
                    computed_hash = hash_functions[attack_type](combination)
                    if computed_hash == target.lower().strip():
                        with self.lock:
                            if not self.found:
                                self.found = True
                                self.result = combination
                                print(f"\n[SUCCESS] Password found: {combination}")
                        return combination
            return None
        
        # Generate combinations in batches to avoid memory issues
        batch_size = 10000
        batch = []
        
        for combination in self.generate_wordlist(min_len, max_len, charset):
            if self.found:
                break
                
            batch.append(combination)
            
            if len(batch) >= batch_size:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [executor.submit(check_combination, combo) for combo in batch]
                    for future in as_completed(futures):
                        if self.found:
                            break
                batch = []
        
        # Process remaining combinations
        if batch and not self.found:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(check_combination, combo) for combo in batch]
                for future in as_completed(futures):
                    if self.found:
                        break
        
        end_time = time.time()
        
        if self.found:
            print(f"Time elapsed: {end_time - start_time:.2f} seconds")
            print(f"Total attempts: {self.attempts:,}")
            return self.result
        else:
            print(f"\n[FAILED] Password not found after {self.attempts:,} attempts")
            print(f"Time elapsed: {end_time - start_time:.2f} seconds")
            return None

def create_charset(include_upper=False, include_digits=False, include_symbols=False, custom_chars=""):
    """Create character set for brute force"""
    charset = string.ascii_lowercase
    
    if include_upper:
        charset += string.ascii_uppercase
    if include_digits:
        charset += string.digits
    if include_symbols:
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if custom_chars:
        charset += custom_chars
    
    return charset

def main():
    parser = argparse.ArgumentParser(
        description="BruteForce CLI Tool - Hash cracking and decoding utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hash attack with wordlist file
  python bruptforce.py hash -t md5 -hash "5d41402abc4b2a76b9719d911017c592" -w wordlist.txt
  
  # Base64 attack with wordlist file
  python bruptforce.py base64 -encoded "aGVsbG8=" -w wordlist.txt
  
  # Brute force MD5 hash
  python bruptforce.py bruteforce -t md5 -target "5d41402abc4b2a76b9719d911017c592" --min-len 1 --max-len 5
  
  # Brute force with custom charset
  python bruptforce.py bruteforce -t sha1 -target "hash_here" --charset "abc123" --min-len 3 --max-len 6
  
  # Generate wordlist combinations to file
  python bruptforce.py generate -o wordlist.txt --min-len 1 --max-len 4 --charset "abc123"

Supported hash types: md5, sha1, sha256, sha512
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Hash attack command
    hash_parser = subparsers.add_parser('hash', help='Perform hash attack using wordlist')
    hash_parser.add_argument('-t', '--type', required=True, 
                           choices=['md5', 'sha1', 'sha256', 'sha512'],
                           help='Hash type')
    hash_parser.add_argument('-hash', '--hash', required=True, help='Target hash to crack')
    hash_parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist file')
    hash_parser.add_argument('--threads', type=int, default=4, help='Number of threads (default: 4)')
    
    # Base64 attack command
    base64_parser = subparsers.add_parser('base64', help='Perform base64 attack using wordlist')
    base64_parser.add_argument('-encoded', '--encoded', required=True, help='Target base64 encoded string')
    base64_parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist file')
    
    # Brute force command
    brute_parser = subparsers.add_parser('bruteforce', help='Perform brute force attack')
    brute_parser.add_argument('-t', '--type', required=True,
                            choices=['md5', 'sha1', 'sha256', 'sha512', 'base64'],
                            help='Attack type')
    brute_parser.add_argument('-target', '--target', required=True, help='Target hash or encoded string')
    brute_parser.add_argument('--min-len', type=int, default=1, help='Minimum length (default: 1)')
    brute_parser.add_argument('--max-len', type=int, default=6, help='Maximum length (default: 6)')
    brute_parser.add_argument('--charset', help='Custom character set')
    brute_parser.add_argument('--include-upper', action='store_true', help='Include uppercase letters')
    brute_parser.add_argument('--include-digits', action='store_true', help='Include digits')
    brute_parser.add_argument('--include-symbols', action='store_true', help='Include symbols')
    brute_parser.add_argument('--threads', type=int, default=4, help='Number of threads (default: 4)')
    
    # Generate wordlist command
    gen_parser = subparsers.add_parser('generate', help='Generate wordlist combinations')
    gen_parser.add_argument('-o', '--output', required=True, help='Output file path')
    gen_parser.add_argument('--min-len', type=int, default=1, help='Minimum length (default: 1)')
    gen_parser.add_argument('--max-len', type=int, default=4, help='Maximum length (default: 4)')
    gen_parser.add_argument('--charset', help='Custom character set')
    gen_parser.add_argument('--include-upper', action='store_true', help='Include uppercase letters')
    gen_parser.add_argument('--include-digits', action='store_true', help='Include digits')
    gen_parser.add_argument('--include-symbols', action='store_true', help='Include symbols')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode base64 string')
    decode_parser.add_argument('encoded', help='Base64 encoded string to decode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    brute_forcer = BruteForcer()
    
    if args.command == 'hash':
        wordlist = brute_forcer.load_wordlist_file(args.wordlist)
        if not wordlist:
            return
        
        result = brute_forcer.hash_attack(args.hash, wordlist, args.type, args.threads)
        
    elif args.command == 'base64':
        wordlist = brute_forcer.load_wordlist_file(args.wordlist)
        if not wordlist:
            return
        
        result = brute_forcer.base64_attack(args.encoded, wordlist)
        
    elif args.command == 'bruteforce':
        if args.charset:
            charset = args.charset
        else:
            charset = create_charset(args.include_upper, args.include_digits, 
                                   args.include_symbols)
        
        result = brute_forcer.brute_force_attack(args.target, args.type, 
                                               args.min_len, args.max_len, 
                                               charset, args.threads)
        
    elif args.command == 'generate':
        if args.charset:
            charset = args.charset
        else:
            charset = create_charset(args.include_upper, args.include_digits, 
                                   args.include_symbols)
        
        print(f"Generating wordlist to {args.output}...")
        print(f"Length range: {args.min_len}-{args.max_len}")
        print(f"Charset: {charset}")
        
        count = 0
        with open(args.output, 'w', encoding='utf-8') as f:
            for combination in brute_forcer.generate_wordlist(args.min_len, args.max_len, charset):
                f.write(combination + '\n')
                count += 1
                if count % 10000 == 0:
                    print(f"Generated: {count:,}")
        
        print(f"Wordlist generated successfully! Total combinations: {count:,}")
        
    elif args.command == 'decode':
        decoded = brute_forcer.base64_decode(args.encoded)
        if decoded:
            print(f"Decoded: {decoded}")
        else:
            print("Failed to decode base64 string")

if __name__ == "__main__":
    main()
