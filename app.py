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

print("Bitcoin Identity #1")
print("* Private key: ", privateKey.secret)
print("* Public key (Point): ", (publicKey.x.num, publicKey.y.num)) 
print("* Public key (SEC Compressed): ", publicKey.sec().hex())
print("* Public key (SEC Uncompressed): ", publicKey.sec(compressed=False).hex())
print("* Public key hash: ", publicKey.hash160().hex())  
print("* Bitcoin address ", publicKey.address(testnet=True))

"""
Bitcoin Identity #1
* Private key:  724746296646138075612064989570816355802000824461885300502117
* Public key (Point):  (35490547311314112975969199385462927466356376524965552000974623035901126229990, 75829577894590863462191837680945451999817850420713104019785938471674831323880)
* Public key (SEC Compressed):  024e76f01bc8ad2b0ca775ee0e392f52f5dd29e779388c6503044592c56f69bfe6
* Public key (SEC Uncompressed):  044e76f01bc8ad2b0ca775ee0e392f52f5dd29e779388c6503044592c56f69bfe6a7a605274e750d1d70a8548c96417d8036c4fb8b6d4296308505c2d8799a42e8
* Public key hash:  363bb1ef1d8791bdbd7e7492ef91decc1eb7295d
* Bitcoin address  mkTiJ6dtXpYJqAremsCZtEww2XFWw3f2WT
"""
