from helper import Curve, Point, Generator, ec_addition, double_and_add, PublicKey 

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

# 
Point.__rmul__ = double_and_add
Point.__add__ = ec_addition


from helper import PublicKey


# identity 1
# ========================

# using a static secret key instead of random for reproducibility 
sk = int.from_bytes(b'super secret identity one', 'big') 
assert 1 <= sk < bitcoin_gen.n 
pk = sk * G

pk_compressed = PublicKey.from_point(pk).encode(compressed=True, hash160=False).hex()
pkh = PublicKey.from_point(pk).encode(compressed=True, hash160=True).hex()
address = PublicKey.from_point(pk).address(net='test', compressed=True)

print("Bitcoin Identity #1")
print("* Secret (Private) Key: ", sk)
print("* Public key (uncompressed): ", (pk.x, pk.y))
print("* Public key (compressed): ", pk_compressed) 
print("* Bitcoin address: ", address)