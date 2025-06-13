import json
import base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

def load_share(filename):
    """Load a share from a file."""
    with open(filename, 'r') as f:
        return json.load(f)

def linear_interpolate_two_points(share1, share2, prime):
    """Reconstruct secret from exactly 2 shares using linear interpolation."""
    x1, y1 = share1
    x2, y2 = share2
    
    # Lagrange interpolation for 2 points to find f(0)
    # L1(0) = (0-x2)/(x1-x2) = -x2/(x1-x2)  
    # L2(0) = (0-x1)/(x2-x1) = -x1/(x2-x1)
    # f(0) = y1*L1(0) + y2*L2(0)
    
    inv_diff = pow(x2 - x1, -1, prime)
    lagrange = (y1 * x2 * inv_diff - y2 * x1 * inv_diff) % prime
    return lagrange

def reconstruct_private_key_fixed(share_file1, share_file2, prime_file):
    """Rebuild the private key from exactly 2 shares."""
    # 1. Load the prime modulus
    with open(prime_file, 'r') as f:
        prime = int(f.read())
    
    # 2. Load exactly 2 shares
    share1_data = load_share(share_file1)
    share2_data = load_share(share_file2)
    
    # 3. Reconstruct each key component using linear interpolation
    key_components = {}
    for component in ['d', 'p', 'q', 'dp', 'dq', 'qinv']:
        share1 = (int(share1_data[component][0]), int(share1_data[component][1]))
        share2 = (int(share2_data[component][0]), int(share2_data[component][1]))
        key_components[component] = linear_interpolate_two_points(share1, share2, prime)
    
    # 4. Rebuild the private key
    private_numbers = RSAPrivateNumbers(
        p=key_components['p'],
        q=key_components['q'],
        d=key_components['d'],
        dmp1=key_components['dp'],
        dmq1=key_components['dq'],
        iqmp=key_components['qinv'],
        public_numbers=RSAPublicNumbers(e=65537, n=key_components['p'] * key_components['q'])
    )
    private_key = private_numbers.private_key()
    
    # 5. Save the reconstructed key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open("reconstructed_key1.priv", 'wb') as f:
        f.write(pem)
    
    print("Successfully reconstructed private key as reconstructed_key1.priv")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python reconstruct.py <share1> <share2>")
        print("Example: python reconstruct.py admin_key_share_1.txt admin_key_share_2.txt")
        sys.exit(1)
    
    reconstruct_private_key_fixed(sys.argv[1], sys.argv[2], "admin_key_prime.txt")