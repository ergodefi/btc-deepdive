from helper import Curve, Point, Generator, ec_addition, double_and_add, PublicKey, TxIn, TxOut, Tx, Script  

# secp256k1 ellptical curve constants - y^2 = x^3 + 7 (mod p)
bitcoin_curve = Curve(
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a = 0x0, 
    b = 0x7, 
)

# generator point 
G = Point(
    bitcoin_curve, 
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)

bitcoin_gen = Generator(
    G = G,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 
)

# point at infinity 
INF = Point(None, None, None) 

# point addition and multiplication
Point.__rmul__ = double_and_add
Point.__add__ = ec_addition

# identity 1
# ========================
# using a static secret key instead of random for reproducibility 
secret_key = int.from_bytes(b'super secret identity one', 'big') 
assert 1 <= secret_key < bitcoin_gen.n 
public_key = secret_key * G

public_key_compressed = PublicKey.from_point(public_key).encode(compressed=True, hash160=False).hex()
public_key_hash = PublicKey.from_point(public_key).encode(compressed=True, hash160=True).hex()
bitcoin_address = PublicKey.from_point(public_key).address(net='test', compressed=True)

print("Bitcoin Identity #1")
print("* Secret (Private) Key: ", secret_key)
print("* Public key (uncompressed): ", (public_key.x, public_key.y))
print("* Public key (compressed): ", public_key_compressed) 
print("* Bitcoin address: ", bitcoin_address)
