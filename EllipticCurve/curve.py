from os import urandom
from abc import ABC, abstractmethod
from dataclasses import dataclass
import string
from typing import Optional
import binascii


def get_inv_mul(e, n):
    gcd, x, _ = xgcd(e, n)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')

    return x % n


def xgcd(a, b):
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b:
        q = a // b
        x1, x0 = x0 - q*x1, x1
        y1, y0 = y0 - q*y1, y1
        a, b = b, a % b

    return a, x0, y0


def modsqrt(a, p):

    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:

        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):

    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def int_length_in_byte(n: int):
    assert n >= 0
    length = 0
    while n:
        n >>= 8
        length += 1
    return length


@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]
    curve: "Curve"

    def is_at_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __post_init__(self):
        if not self.is_at_infinity() and not self.curve.is_on_curve(self):
            raise ValueError("The point is not on the curve.")

    def __str__(self):
        if self.is_at_infinity():
            return f"Point(At infinity, Curve={str(self.curve)})"
        else:
            return f"Point(X={self.x}, Y={self.y}, Curve={str(self.curve)})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __neg__(self):
        return self.curve.neg_point(self)

    def __add__(self, other):
        return self.curve.add_point(self, other)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        negative = - other
        return self.__add__(negative)

    def __mul__(self, scalar: int):
        return self.curve.mul_point(scalar, self)

    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)


@dataclass
class Curve(ABC):
    name: str
    a: int
    b: int
    p: int
    n: int
    G_x: int
    G_y: int

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (
            self.a == other.a and self.b == other.b and self.p == other.p and
            self.n == other.n and self.G_x == other.G_x and self.G_y == other.G_y
        )

    @property
    def G(self) -> Point:
        return Point(self.G_x, self.G_y, self)

    @property
    def INF(self) -> Point:
        return Point(None, None, self)

    def is_on_curve(self, P: Point) -> bool:
        if P.curve != self:
            return False
        return P.is_at_infinity() or self._is_on_curve(P)

    @abstractmethod
    def _is_on_curve(self, P: Point) -> bool:
        pass

    def add_point(self, P: Point, Q: Point) -> Point:
        if (not self.is_on_curve(P)) or (not self.is_on_curve(Q)):
            raise ValueError("The points are not on the curve.")
        if P.is_at_infinity():
            return Q
        elif Q.is_at_infinity():
            return P

        if P == -Q:
            return self.INF
        if P == Q:
            return self._double_point(P)

        return self._add_point(P, Q)

    @abstractmethod
    def _add_point(self, P: Point, Q: Point) -> Point:
        pass

    @abstractmethod
    def _double_point(self, P: Point) -> Point:
        pass

    def mul_point(self, d: int, P: Point) -> Point:

        if not self.is_on_curve(P):
            raise ValueError("The point is not on the curve.")
        if P.is_at_infinity():
            return self.INF
        if d == 0:
            return self.INF

        res = self.INF
        is_negative_scalar = d < 0
        d = -d if is_negative_scalar else d
        tmp = P
        while d:
            if d & 0x1 == 1:
                res = self.add_point(res, tmp)
            tmp = self.add_point(tmp, tmp)
            d >>= 1
        if is_negative_scalar:
            return -res
        else:
            return res

    def neg_point(self, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("The point is not on the curve.")
        if P.is_at_infinity():
            return self.INF

        return self._neg_point(P)

    @abstractmethod
    def _neg_point(self, P: Point) -> Point:
        pass

    @abstractmethod
    def compute_y(self, x: int) -> int:
        pass

    def encode_point(self, plaintext: bytes) -> Point:
        plaintext = len(plaintext).to_bytes(1, byteorder="big") + plaintext
        while True:
            x = int.from_bytes(plaintext, "big")
            y = self.compute_y(x)
            if y:

                return Point(x, y, self)
            plaintext += urandom(1)

    def decode_point(self, M: Point) -> string:
        byte_len = int_length_in_byte(M.x)
        plaintext_len = (M.x >> ((byte_len - 1) * 8)) & 0xff
        plaintext = ((M.x >> ((byte_len - plaintext_len - 1) * 8))
                     & (int.from_bytes(b"\xff" * plaintext_len, "big")))

        return plaintext.to_bytes(plaintext_len, byteorder="big")


class ShortWeierstrassCurve(Curve):

    def _is_on_curve(self, P: Point) -> bool:
        left = P.y * P.y
        right = (P.x * P.x * P.x) + (self.a * P.x) + self.b
        return (left - right) % self.p == 0

    def _add_point(self, P: Point, Q: Point) -> Point:

        delta_x = P.x - Q.x
        delta_y = P.y - Q.y
        s = delta_y * get_inv_mul(delta_x, self.p)
        res_x = (s * s - P.x - Q.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def _double_point(self, P: Point) -> Point:

        s = (3 * P.x * P.x + self.a) * get_inv_mul(2 * P.y, self.p)
        res_x = (s * s - 2 * P.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def _neg_point(self, P: Point) -> Point:
        return Point(P.x, -P.y % self.p, self)

    def compute_y(self, x) -> int:
        right = (x * x * x + self.a * x + self.b) % self.p
        y = modsqrt(right, self.p)
        return y


P256 = ShortWeierstrassCurve(
    name="P256",
    a=-3,
    b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    G_x=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    G_y=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
)

secp256k1 = ShortWeierstrassCurve(
    name="secp256k1",
    a=0,
    b=7,
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    G_x=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    G_y=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)
secp192r1 = ShortWeierstrassCurve(
    name="secp192r1",
    a=0xfffffffffffffffffffffffffffffffefffffffffffffffc,
    b=0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
    p=0xfffffffffffffffffffffffffffffffeffffffffffffffff,
    n=0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
    G_x=0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
    G_y=0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
)
secp224k1 = ShortWeierstrassCurve(
    name="secp224k1",
    a=0x00000000000000000000000000000000000000000000000000000000,
    b=0x00000000000000000000000000000000000000000000000000000005,
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d,
    n=0x10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7,
    G_x=0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c,
    G_y=0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5
)
