# BruteForce CLI Tool

A comprehensive command-line brute force tool for hash cracking and decoding operations. Supports multiple hash types (MD5, SHA1, SHA256, SHA512) and Base64 encoding/decoding with both dictionary attacks and brute force capabilities.

## Features

- **Multiple Hash Support**: MD5, SHA1, SHA256, SHA512
- **Base64 Encoding/Decoding**: Attack and decode Base64 strings
- **Dictionary Attacks**: Use wordlist files for efficient attacks
- **Brute Force Attacks**: Generate combinations on-the-fly
- **Multi-threading**: Configurable thread count for faster attacks
- **Flexible Character Sets**: Custom character sets for targeted attacks
- **Wordlist Generation**: Create custom wordlists with specified parameters
- **Progress Tracking**: Real-time progress updates during attacks

## Installation

### Requirements
- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

### Setup
1. Clone or download the project
2. Make the script executable (Linux/Mac):
   ```bash
   chmod +x bruptforce.py
   ```

## Usage

The tool provides several commands for different types of attacks:

### Hash Attacks (Dictionary-based)

Attack hash using a wordlist file:

```bash
# MD5 hash attack
python bruptforce.py hash -t md5 --hash "5d41402abc4b2a76b9719d911017c592" -w wordlist.txt

# SHA256 hash attack with 8 threads
python bruptforce.py hash -t sha256 --hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" -w wordlist.txt --threads 8
```

### Base64 Attacks

Attack Base64 encoded strings:

```bash
# Base64 attack using wordlist
python bruptforce.py base64 --encoded "aGVsbG8=" -w wordlist.txt
```

### Brute Force Attacks

Generate combinations and attack:

```bash
# Brute force MD5 with default charset (lowercase + digits)
python bruptforce.py bruteforce -t md5 --target "5d41402abc4b2a76b9719d911017c592" --min-len 1 --max-len 5

# Brute force with custom charset
python bruptforce.py bruteforce -t sha1 --target "your_hash_here" --charset "abc123!@#" --min-len 3 --max-len 6

# Brute force with extended character sets
python bruptforce.py bruteforce -t md5 --target "your_hash_here" --min-len 1 --max-len 4 --include-upper --include-digits --include-symbols

# Brute force Base64
python bruptforce.py bruteforce -t base64 --target "aGVsbG8=" --min-len 1 --max-len 8 --include-upper --include-digits
```

### Wordlist Generation

Generate custom wordlists:

```bash
# Generate basic wordlist (lowercase + digits, length 1-4)
python bruptforce.py generate -o my_wordlist.txt --min-len 1 --max-len 4

# Generate with extended character sets
python bruptforce.py generate -o complex_wordlist.txt --min-len 3 --max-len 5 --include-upper --include-digits --include-symbols

# Generate with custom charset
python bruptforce.py generate -o custom_wordlist.txt --charset "abcdef123" --min-len 2 --max-len 6
```

### Simple Base64 Decode

Decode a Base64 string directly:

```bash
python bruptforce.py decode "aGVsbG8gd29ybGQ="
```

## Command Reference

### Main Commands

| Command | Description |
|---------|-------------|
| `hash` | Dictionary attack against hash |
| `base64` | Dictionary attack against Base64 |
| `bruteforce` | Brute force attack (generates combinations) |
| `generate` | Generate wordlist file |
| `decode` | Simple Base64 decoder |

### Hash Attack Options

| Option | Description | Required |
|--------|-------------|----------|
| `-t, --type` | Hash type (md5, sha1, sha256, sha512) | Yes |
| `--hash` | Target hash to crack | Yes |
| `-w, --wordlist` | Path to wordlist file | Yes |
| `--threads` | Number of threads (default: 4) | No |

### Base64 Attack Options

| Option | Description | Required |
|--------|-------------|----------|
| `--encoded` | Target Base64 encoded string | Yes |
| `-w, --wordlist` | Path to wordlist file | Yes |

### Brute Force Options

| Option | Description | Required |
|--------|-------------|----------|
| `-t, --type` | Attack type (md5, sha1, sha256, sha512, base64) | Yes |
| `--target` | Target hash or encoded string | Yes |
| `--min-len` | Minimum length (default: 1) | No |
| `--max-len` | Maximum length (default: 6) | No |
| `--charset` | Custom character set | No |
| `--include-upper` | Include uppercase letters | No |
| `--include-digits` | Include digits | No |
| `--include-symbols` | Include symbols | No |
| `--threads` | Number of threads (default: 4) | No |

### Generate Options

| Option | Description | Required |
|--------|-------------|----------|
| `-o, --output` | Output file path | Yes |
| `--min-len` | Minimum length (default: 1) | No |
| `--max-len` | Maximum length (default: 4) | No |
| `--charset` | Custom character set | No |
| `--include-upper` | Include uppercase letters | No |
| `--include-digits` | Include digits | No |
| `--include-symbols` | Include symbols | No |

## Examples

### Example 1: Crack MD5 Hash with Wordlist

```bash
# Create a simple wordlist
echo -e "hello\nworld\npassword\n123456\nadmin" > simple_wordlist.txt

# Attack MD5 hash of "hello"
python bruptforce.py hash -t md5 --hash "5d41402abc4b2a76b9719d911017c592" -w simple_wordlist.txt
```

### Example 2: Brute Force Short Password

```bash
# Brute force 3-character password with lowercase letters only
python bruptforce.py bruteforce -t md5 --target "098f6bcd4621d373cade4e832627b4f6" --min-len 3 --max-len 3 --charset "abcdefghijklmnopqrstuvwxyz"
```

### Example 3: Generate and Use Custom Wordlist

```bash
# Generate wordlist with digits and lowercase letters, length 2-4
python bruptforce.py generate -o custom.txt --min-len 2 --max-len 4 --include-digits

# Use the generated wordlist for attack
python bruptforce.py hash -t sha1 --hash "your_hash_here" -w custom.txt
```

### Example 4: Base64 Attack

```bash
# Create wordlist for Base64 attack
echo -e "hello\nworld\nsecret\ntest" > b64_wordlist.txt

# Attack Base64 encoded "hello" (aGVsbG8=)
python bruptforce.py base64 --encoded "aGVsbG8=" -w b64_wordlist.txt
```

## Performance Tips

1. **Use Wordlists First**: Dictionary attacks are much faster than brute force
2. **Optimize Thread Count**: Start with 4-8 threads, adjust based on your CPU
3. **Limit Brute Force Length**: Each additional character exponentially increases time
4. **Use Targeted Character Sets**: Reduce character set size when possible

## Common Hash Examples

Here are some test hashes you can practice with:

| Original | MD5 | Type |
|----------|-----|------|
| hello | 5d41402abc4b2a76b9719d911017c592 | MD5 |
| world | 7d793037a0760186574b0282f2f435e7 | MD5 |
| test | 098f6bcd4621d373cade4e832627b4f6 | MD5 |
| 123 | 202cb962ac59075b964b07152d234b70 | MD5 |

| Original | SHA1 |
|----------|------|
| hello | aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d |
| password | 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 |

| Original | Base64 |
|----------|--------|
| hello | aGVsbG8= |
| world | d29ybGQ= |
| test | dGVzdA== |

## Security Notice

This tool is designed for:
- Educational purposes
- Penetration testing with proper authorization
- Recovery of your own forgotten passwords
- Security research

**Important**: Only use this tool on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

## Troubleshooting

### Common Issues

1. **"Wordlist file not found"**
   - Check the file path is correct
   - Ensure the file exists and is readable

2. **Slow performance**
   - Reduce thread count if system becomes unresponsive
   - Use shorter password lengths for brute force
   - Consider using wordlist attacks instead of brute force

3. **Memory issues with large wordlists**
   - The tool processes wordlists in chunks to manage memory
   - Very large wordlists (>1GB) may still cause issues on low-memory systems

4. **No results found**
   - Verify the hash format is correct
   - Check if the password might be longer than your max-len setting
   - Consider expanding the character set

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

Well, this tools is created by me to do some challenge on lab for workshop purpose so~ ya maybe will have some improve in the future? who know hehe

## License


This project is open source and available under the MIT License.
