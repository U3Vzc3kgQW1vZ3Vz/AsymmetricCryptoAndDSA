import random
from os import urandom
import string
from typing import Callable, Tuple
from dataclasses import dataclass

from curve import Curve, Point
import hashlib

def Sha512Hash(input):
    return hashlib.sha512(input).hexdigest()
def inverse(u, v):

    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = divmod(u3, v3)[0]
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1 < 0:
        u1 = u1 + v
    return u1
@dataclass
class ElGamal:
    curve: Curve

    def encrypt(self, plaintext: bytes, public_key: Point,
                randfunc: Callable = None) -> Tuple[Point, Point]:

        return self.encrypt_bytes(plaintext, public_key, randfunc)

    def decrypt(self, private_key: int, C1: Point, C2: Point) -> string:
        return self.decrypt_bytes(private_key, C1, C2)

    def encrypt_bytes(self, plaintext: bytes, public_key: Point,
                      randfunc: Callable = None) -> Tuple[Point, Point]:
        

        M = self.curve.encode_point(plaintext)
        return self.encrypt_point(M, public_key, randfunc)

    def decrypt_bytes(self, private_key: int, C1: Point, C2: Point) -> bytes:
        M = self.decrypt_point(private_key, C1, C2)
        return self.curve.decode_point(M)

    def encrypt_point(self, plaintext: Point, public_key: Point,
                      randfunc: Callable = None) -> Tuple[Point, Point]:
        randfunc = randfunc or urandom
        

        G = self.curve.G
        M = plaintext

        random.seed(randfunc(1024))
        k = random.randint(1, self.curve.n)

        C1 = k * G
        C2 = M + k * public_key
        return C1, C2
    def sign(self,private_key:int,plaintext:string,G:Point,r=-1,s=-1)->Tuple[Point,Point]:
        k=random.randint(1,self.curve.n-1)
        kG=k*G
        r=kG.x%self.curve.n
        if r==0:
            return self.sign(self,private_key,plaintext,G)
        h=int(Sha512Hash(plaintext),16)
        s=((h+private_key*r)*inverse(k,self.curve.n))%self.curve.n
        if s==0:
          return self.sign(self,private_key,plaintext,G)
        return r,s
    def verify(self, public_key:Point,plaintext: string,r:int,s:int)->bool:
        if r>self.curve.n-1 or r<1 or s>self.curve.n-1 or s<1:
            return False
        w=inverse(s,self.curve.n)
        h=int(Sha512Hash(plaintext),16)
        u1=(h*w)%self.curve.n
        u2=(r*w)%self.curve.n
        X=u1*self.curve.G+u2*public_key
        v=X.x%self.curve.n
        return v==r
    def decrypt_point(self, private_key: int, C1: Point, C2: Point) -> Point:
        M = C2 + (self.curve.n - private_key) * C1
        return M
