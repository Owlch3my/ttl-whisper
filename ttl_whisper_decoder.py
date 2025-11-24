#!/usr/bin/env python3
"""TTLwhisper Decoder - Extract steganographic morse from PCAP"""
import sys

try:
    from scapy.all import rdpcap, ICMP
except ImportError:
    print("[!] Install scapy: pip install scapy")
    sys.exit(1)

MORSE_CODE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '--..--': ',', '.-.-.-': '.', '..--.-': '_',
    '..--..': '?', '-.-.-.': ';', '---...': ':', '.----.': "'",
    '-....-': '-', '.--.-.': '@', '-.-.--': '!'
}

def ttl_to_char(ttl):
    """Map TTL value to morse character"""
    if 32 <= ttl <= 64:
        return '.'
    elif 65 <= ttl <= 96:
        return '-'
    elif 97 <= ttl <= 128:
        return '|'
    elif 129 <= ttl <= 160:
        return '/'
    else:
        return None  # Jitter/noise

def decode_morse(morse_string):
    """Decode morse to plaintext"""
    words = morse_string.split('/')
    decoded_words = []
    
    for word in words:
        letters = word.split('|')
        decoded_letters = []
        for letter in letters:
            if letter in MORSE_CODE:
                decoded_letters.append(MORSE_CODE[letter])
            elif letter:  # Non-empty but unknown
                decoded_letters.append('?')
        decoded_words.append(''.join(decoded_letters))
    
    return ' '.join(decoded_words)

def extract_from_pcap(pcap_file):
    """Extract hidden message from PCAP file"""
    print(f"[*] Reading {pcap_file}...")
    packets = rdpcap(pcap_file)
    
    icmp_packets = [p for p in packets if ICMP in p and p[ICMP].type == 8]
    print(f"[*] Found {len(icmp_packets)} ICMP echo requests\n")
    
    if not icmp_packets:
        print("[!] No ICMP packets found")
        return
    
    # Extract TTL values and convert to morse
    morse_string = ''
    ttl_values = []
    
    for pkt in icmp_packets:
        ttl = pkt.ttl
        ttl_values.append(ttl)
        char = ttl_to_char(ttl)
        if char:
            morse_string += char
    
    print(f"[+] TTL sequence: {ttl_values}\n")
    print(f"[+] Morse code: {morse_string}\n")
    
    # Decode morse
    decoded = decode_morse(morse_string)
    print(f"[+] Decoded message: {decoded}\n")
    
    # Show letter-by-letter breakdown
    print("[*] Breakdown:")
    for i, letter_morse in enumerate(morse_string.split('|')):
        if letter_morse and letter_morse != '/':
            decoded_char = MORSE_CODE.get(letter_morse, '?')
            print(f"  {letter_morse:8} -> {decoded_char}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        print(f"Example: {sys.argv[0]} capture.pcap")
        sys.exit(1)
    
    extract_from_pcap(sys.argv[1])
