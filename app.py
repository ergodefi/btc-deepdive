from helper import Curve, Point, Generator, ec_addition, double_and_add

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

# point addition and multiplicationw
Point.__rmul__ = double_and_add
Point.__add__ = ec_addition
3
# identity 1
# ========================
# using a static secret key instead of random for reproducibility 
secret_key = int.from_bytes(b'super secret identity one', 'big') 
assert 1 <= secret_key < bitcoin_gen.n 
public_key = secret_key * G

from helper import PublicKey

public_key_compressed = PublicKey.from_point(public_key).encode(compressed=True, hash160=False).hex()
public_key_hash = PublicKey.from_point(public_key).encode(compressed=True, hash160=True).hex()
bitcoin_address = PublicKey.from_point(public_key).address(net='test', compressed=True)

print("Bitcoin Identity #1")
print("* Secret (Private) Key: ", secret_key)
print("* Public key (uncompressed): ", (public_key.x, public_key.y))
print("* Public key (compressed): ", public_key_compressed) 
print("* Public key hash: ", public_key_hash) 
print("* Bitcoin address (base58check): ", bitcoin_address)


# identity 2 
# ========================
secret_key2 = int.from_bytes(b'another secret identity two', 'big') # for reproducibility 
assert 1 <= secret_key2 < bitcoin_gen.n
public_key2 = secret_key2 * G
public_key2_compressed = PublicKey.from_point(public_key2).encode(compressed=True, hash160=False).hex()
public_key_hash2 = PublicKey.from_point(public_key2).encode(compressed=True, hash160=True).hex()
bitcoin_address2 = PublicKey.from_point(public_key2).address(net='test', compressed=True)

print("Bitcoin Identity #2")
print("* Secret (Private) Key: ", secret_key2)
print("* Public key (uncompressed): ", (public_key2.x, public_key2.y))
print("* public key (compressed): ", public_key2_compressed) 
print("* Public key hash: ", public_key_hash2) 
print("* Bitcoin address: ", bitcoin_address2)

from helper import TxIn, TxOut, Script, Tx

# transaction input #1 
tx_in = TxIn(
    prev_tx = bytes.fromhex('6707af5c6d5257067c969fcf7f875e6ad9ad3143e3025f8c391683b23cff9c24'), 
    prev_index = 1, # the 2nd output 
    script_sig = None, # signature to be inserted later 
    sequence = 0xffffffff, # almost never used and default to 0xffffffff
)

# transaction output #1
tx_out1 = TxOut(
    amount = 75000,
)

# transaction output #2
tx_out2 = TxOut(
    amount = 22000,
)

# 75000 + 22000 = 97000, which means 3000 sats are paid to the miner as transaction fee 

from helper import sign, create_script_sig, generate_tx_id

output1_pkh = PublicKey.from_point(public_key2).encode(compressed=True, hash160=True)  
output2_pkh = PublicKey.from_point(public_key).encode(compressed=True, hash160=True)

# 118, 169, 136 and 172 are op_codes. # Refer to https://en.bitcoin.it/wiki/Script for more info
output1_script = Script([118, 169, output1_pkh, 136, 172])
output2_script = Script([118, 169, output2_pkh, 136, 172])

output1_script.encode().hex() # output 1 in hex: 1976a91400f6739d5e8b4017a9eebe413249ed3949e65e2488ac
output2_script.encode().hex() # output 2 in hex: 1976a91400f6739d5e8b4017a9eebe413249ed3949e65e2488ac

tx_out1.script_pubkey = output1_script # adding script_pubkey to output 1
tx_out2.script_pubkey = output2_script # adding script_pubkey to output 2

# retrieve previous transaction output public key hash 
public_key_hash = PublicKey.from_point(public_key).encode(compressed=True, hash160=True)

# constructing the previous tx locking script 
prev_tx_script_pubkey = Script([118, 169, public_key_hash, 136, 172])

# adding the locking script as placeholder for input digital signature
tx_in.prev_tx_script_pubkey = prev_tx_script_pubkey 

print("Previous tx locking script:", prev_tx_script_pubkey.encode().hex())

# construct the transaction 
tx = Tx(
    version = 1, # currently there's just version 1
    tx_ins = [tx_in],
    tx_outs = [tx_out1, tx_out2],
    locktime = 0,
)

message = tx.encode(sig_index = 0)
print("Message for signing: ", message.hex())

# generate the signature 
sig = sign(secret_key, message)
print("The digital signature:", sig)

# encode the signature as DER encoding 
sig_bytes = sig.encode()
print("The encoded digital signature:", sig_bytes.hex())

# generate the script_sig (DER encoded signature + public key)
script_sig = create_script_sig(sig_bytes, public_key)

# adding script_sig to the transaction input 
tx_in.script_sig = script_sig

# print the full transaction as byte and hex!
print("Completed transaction (in bytestring):", tx)
print("---")
print("Completed transaction (in hex):", tx.encode().hex())

# once tx goes through, this will be its id (which is a hash of the entire transaction)
transaction_id = generate_tx_id(tx)
print("Transaction id:", transaction_id) 
