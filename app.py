from ecc import PrivateKey
from helper import decode_base58
from script import p2pkh_script, Script 
from tx import TxIn, TxOut, Tx
from helper import SIGHASH_ALL

# identity 1
# =====================
secret = int.from_bytes(b'super secret identity one', 'big')
privateKey = PrivateKey(secret)
publicKey = privateKey.point 

# print("Bitcoin Identity #1")
# print("* Private key: ", privateKey.secret)
# print("* Public key (Point): ", (publicKey.x.num, publicKey.y.num)) 
# print("* Public key (SEC Compressed): ", publicKey.sec().hex())
# print("* Public key (SEC Uncompressed): ", publicKey.sec(compressed=False).hex())
# print("* Public key hash: ", publicKey.hash160().hex())  
# print("* Bitcoin address ", publicKey.address(testnet=True))

# identity 2 
# ========================
secret2 = int.from_bytes(b'another secret identity two', 'big')
privateKey2 = PrivateKey(secret2)
publicKey2 = privateKey2.point

# print()
# print("Bitcoin Identity #2")
# print("* Private key: ", privateKey2.secret)
# print("* Public key (Point): ", (publicKey2.x.num, publicKey2.y.num)) 
# print("* Public key (SEC Compressed): ", publicKey2.sec().hex())
# print("* Public key (SEC Uncompressed): ", publicKey2.sec(compressed=False).hex())
# print("* Public key hash: ", publicKey2.hash160().hex())  
# print("* Bitcoin address ", publicKey2.address(testnet=True))

# Transaction 
# =====================

# STEP 1:   Create TxIn objects to store transaction inputs 
#           The script_sig cannot be generated yet 

tx_in = TxIn(
    prev_tx = bytes.fromhex('6707af5c6d5257067c969fcf7f875e6ad9ad3143e3025f8c391683b23cff9c24'),
    prev_index = 1
)

# STEP 2:   Create TxOut objects to store transaction outputs 
# Create output #1 object
tx_out1 = TxOut(
    amount = 7500,
    script_pubkey = p2pkh_script(publicKey2.hash160()) 
    # OP_DUP OP_HASH160 00f6739d5e8b4017a9eebe413249ed3949e65e24 OP_EQUALVERIFY OP_CHECKSIG
)  

# Create output #2 object
tx_out2 = TxOut(
    amount = 2200,
    script_pubkey = p2pkh_script(publicKey.hash160()) 
    # OP_DUP OP_HASH160 363bb1ef1d8791bdbd7e7492ef91decc1eb7295d OP_EQUALVERIFY OP_CHECKSIG
)

# STEP 3 - Create the transaction object to consolidate the info 

tx = Tx(
    version = 1,
    tx_ins = [tx_in],
    tx_outs = [tx_out1, tx_out2],
    locktime = 0,
    testnet=True
)

# STEP 4 - Sign the transaction to generate digital signature 
z = tx.sig_hash(0) 
rs_values = privateKey.sign(z)
der = rs_values.der()
sig = der + SIGHASH_ALL.to_bytes(1, 'big')
script_sig = Script([sig, privateKey.point.sec()])

# print("r-value:", rs_values.r)
# print("s-value:", rs_values.s)
# print("DER signature:", der.hex())
# print("script_sig:", script_sig)


# STEP 5 - the transaction together 
tx.tx_ins[0].script_sig = script_sig  # incorporate script_sig into transaction 

# print(tx.serialize()) # print raw format
# print(tx.serialize().hex()) # print hex format 


# Verify the transaction to unlock the UTXO
# =====================

print(tx.verify_input(0)) # True
# print(tx.verify()) # True
