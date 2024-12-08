from curve import (
    P256, secp256k1,secp192r1,secp224k1
)
from cipher import ElGamal
from key import gen_keypair




def test():

    # curve = secp192r1
    # curve = secp224k1
    curve=secp256k1
    message = "this is a plain from nam to bob"
    print("The message is as follows:")
    print(message)
    print(f"\t------------------------")
    
    pri_key, pub_key = gen_keypair(curve)
    print("This is the private key :d= ", pri_key)
    print("This is the public key :Q= (x=", pub_key.x,",y=",pub_key.y,")")
    cipher_elg = ElGamal(curve)
    C1, C2 = cipher_elg.encrypt(message.encode('utf-8'), pub_key)

    print("The cipher is as follows:")
    print("c1=(x=", C1.x,",y=",C1.y,")")
    print("c2=(x=", C2.x,",y=",C2.y,")")
    print(f"\t------------------------")
    plaintext = cipher_elg.decrypt(pri_key, C1, C2)
    print("The decrypted plaintext is as follows:")
    print(plaintext.decode("utf-8"))
    print(f"\t------------------------")
    r, s = cipher_elg.sign(pri_key, plaintext, pub_key.curve.G)
    print("The signature is as follows:")   
    print("r=", r, "s=", s)
    print(f"\t------------------------")
    if cipher_elg.verify(pub_key, plaintext, r, s):
        print("Signature is authentic")


test()
