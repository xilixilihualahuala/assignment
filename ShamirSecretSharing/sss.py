import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
import sympy
import base64
import json

def generate_prime_larger_than(n_bits):
    """Generate a prime larger than 2^n_bits."""
    lower_bound = 2 ** n_bits
    return sympy.nextprime(lower_bound)

def generate_shares_linear(secret, prime):
    """Generate 3 shares using linear equation y = ax + secret (mod p)."""
    # Generate random coefficient 'a'
    a = random.randint(1, prime - 1)
    
    # Generate shares using y = ax + secret (mod p) for x = 1, 2, 3
    shares = []
    for x in [1, 2, 3]:
        y = (a * x + secret) % prime
        shares.append((x, y))
    
    return shares

def save_shares(shares, filename_prefix):
    """Save shares to files."""
    share_files = []
    for i, (x, y) in enumerate(shares):
        filename = f"{filename_prefix}_share_{i+1}.txt"
        with open(filename, 'w') as f:
            f.write(f"{x}:{base64.b64encode(y.to_bytes((y.bit_length() + 7) // 8, 'big')).decode()}")
        share_files.append(filename)
    return share_files

def split_private_key_fixed(key_filename):
    """Split an RSA private key into 3 shares with threshold=2 using linear equation."""
    # 1. Load the private key
    with open(key_filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        private_numbers = private_key.private_numbers()
    
    # 2. Extract all key components
    key_components = {
        'd': private_numbers.d,
        'p': private_numbers.p,
        'q': private_numbers.q,
        'dp': private_numbers.dmp1,
        'dq': private_numbers.dmq1,
        'qinv': private_numbers.iqmp
    }
    
    # 3. Choose a large prime (bigger than any key component)
    max_bits = max(c.bit_length() for c in key_components.values())
    prime = generate_prime_larger_than(max_bits + 1)
    
    # 4. Split each component into 3 shares using linear equation
    shares = {}
    for name, value in key_components.items():
        shares[name] = generate_shares_linear(value, prime)
    
    # 5. Save shares to files
    saved_files = []
    for i in range(3):  # Fixed to 3 shares
        share_data = {name: shares[name][i] for name in key_components}
        filename = f"admin_key_share_{i+1}.txt"
        with open(filename, 'w') as f:
            json.dump(share_data, f)
        saved_files.append(filename)
    
    # 6. Save the prime modulus (needed for reconstruction)
    with open("admin_key_prime.txt", 'w') as f:
        f.write(str(prime))
    
    print(f"Successfully split key into 3 shares (threshold=2) using linear equation y = ax + secret")
    print(f"Prime modulus saved to admin_key_prime.txt")
    print(f"Share files: {', '.join(saved_files)}")



if __name__ == "__main__":
    split_private_key_fixed("admin1.priv")