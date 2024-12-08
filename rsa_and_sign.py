#!/bin/env python
import string
from typing import Tuple
from random import randrange, randint
from abc import ABC


def get_prime(n_bits, n_tests):
    x = get_randbitsodd(n_bits)
    while not is_prime(x, n_tests):
        x = get_randbitsodd(n_bits)
    return x


def is_prime(number, n_tests):
    def find_t_u(n):
        u, t = n - 1, 0
        while u % 2 == 0:
            t += 1
            u //= 2
        return t, u

    def witness(a, u, t, n):
        x = pow(a, u, n)
        if x == 1:
            return False
        for i in range(t):
            if pow(a, 2**i*u, n) == (n-1):
                return False
        return True

    assert (number != 2)

    assert (number % 2 != 0)

    t, u = find_t_u(number)
    for _ in range(n_tests):
        a = randint(2, number-1)
        if witness(a, u, t, number):
            return False
    return True


def get_small_rel_prime(phi):
    for e in range(3, phi, 2):
        a, _, _ = xgcd(e, phi)
        if a == 1:
            return e
    raise Exception("Could not find e parameter")


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


def get_randbitsodd(n_bits):
    return randrange(pow(2, n_bits-1)+1, pow(2, n_bits), 2)


class Key(ABC):
    def __init__(self, x, n, key_size):
        self.x = x
        self.n = n
        self.key_size = key_size
        # self.pkcs1_seq = univ.Sequence()
        # self.pkcs1_seq.setComponentByPosition(0, univ.Integer(self.x))
        # self.pkcs1_seq.setComponentByPosition(1, univ.Integer(self.n))


def encode(plaintext: string, key_size: int) -> list:
    byte_array = bytearray(plaintext, 'utf-16')

    z = []

    k = key_size//8

    j = -1 * k

    num = 0

    for i in range(len(byte_array)):

        if i % k == 0:
            j += k
            num = 0
            z.append(0)

        z[j//k] += byte_array[i]*(2**(8*(i % k)))

    return z


def decode(encoded_text: list, key_size: int) -> string:

    bytes_array = []

    k = key_size//8

    for num in encoded_text:
        for i in range(k):

            temp = num

            for j in range(i+1, k):

                temp = temp % (2**(8*j))

            letter = temp // (2**(8*i))

            bytes_array.append(letter)

            num = num - (letter*(2**(8*i)))

    decoded_text = bytearray(b for b in bytes_array).decode('utf-16')

    return decoded_text


class PrivateKey(Key):

    def decrypt(self, cipher: string)->string:
        content_blocks = []
        cipher_blocks = cipher.split()
        for cipher in cipher_blocks:
            text_block = pow(int(cipher), self.x, self.n)
            content_blocks.append(text_block)

        decrypted_text = decode(content_blocks, self.key_size)
        decrypted_text = "".join([ch for ch in decrypted_text if ch != '\x00'])
        return decrypted_text

    def sign(self, plaintext:string)->string:
        sign_blocks = []
        encoded_text = encode(plaintext, self.key_size)
        for text in encoded_text:
            text_block = pow(int(text), self.x, self.n)
            sign_blocks.append(text_block)
        signature_str = ""
        for block in sign_blocks:
            signature_str += str(block)+' '
        return signature_str


class PublicKey(Key):

    def encrypt(self, plaintext:string)->string:
        cipher_blocks = []
        encoded_text = encode(plaintext, self.key_size)

        for chunk in encoded_text:

            cipher = pow(chunk, self.x, self.n)
            cipher_blocks.append(str(cipher))
        encrypted_str = ""
        for block in cipher_blocks:
            encrypted_str += str(block) + ' '

        return encrypted_str

    def verify(self, plaintext:string, signature:string)->bool:
        sign_blocks = signature.split(' ')
        encoded_text = encode(plaintext, self.key_size)
        i = 0
        for text in encoded_text:
            sign = int(sign_blocks[i])
            right_bracket = pow(sign, self.x, self.n)
            left_bracket = int(text) % self.n
            i += 1
            if right_bracket != left_bracket:
                return False
        return True


def generate_keys(key_size:int, n_tests=30)->Tuple[PublicKey,PrivateKey]:
    assert (key_size >= 16)
    p = get_prime(key_size//2, n_tests)
    q = get_prime(key_size//2, n_tests)
    n = p*q
    phi = (p - 1)*(q - 1)
    e = get_small_rel_prime(phi)
    d = get_inv_mul(e, phi)
    return PublicKey(e, n, key_size), PrivateKey(d, n, key_size)


def test():
    key_size = 2048
    public_key, private_key = generate_keys(key_size)
    print("This is the public key: e=", public_key.x)
    print("This is the private key: d=", private_key.x)
    message = "this is a test with a long string to check the performance of the cryptosystem and its handling of numerous characters"
    print("The message is as follows:")
    print(message)
    print(f"\t------------------------")
    cipher = public_key.encrypt(message)
    print("The cipher is as follows:")
    print(cipher)
    print(f"\t------------------------")
    plain = private_key.decrypt(cipher)
    print("The decrypted plaintext is as follows:")
    print(plain)
    print(f"\t------------------------")
    sign = private_key.sign(message)
    print("The signature is as follows:")
    print(sign)
    print(f"\t------------------------")
    if public_key.verify(plain, sign):
        print("Correct signature")


test()
