import random
import string


class PrivateKey(object):
    def __init__(self, p=None, g=None, x=None, key_size=0):
        self.p = p
        self.g = g
        self.x = x
        self.key_size = key_size


class PublicKey(object):
    def __init__(self, p=None, g=None, h=None, key_size=0):
        self.p = p
        self.g = g
        self.h = h
        self.key_size = key_size


def gcd(a, b):
    while b != 0:
        c = a % b
        a = b
        b = c

    return a


def get_inv_mul(e, n):
    gcd, x, _ = xgcd(e, n)
    if gcd != 1:
        raise Exception('Modular get_inv_mul does not exist')

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
        a = random.randint(2, number-1)
        if witness(a, u, t, number):
            return False
    return True


def get_randbitsodd(n_bits):
    return random.randrange(pow(2, n_bits-1)+1, pow(2, n_bits), 2)


def get_prime(n_bits, n_tests):
    x = get_randbitsodd(n_bits)
    while not is_prime(x, n_tests):
        x = get_randbitsodd(n_bits)
    return x


def find_primitive_root(p):
    if p == 2:
        return 1

    p1 = 2
    p2 = (p-1) // p1

    while (1):
        g = random.randint(2, p-1)

        if not (pow(g, (p-1)//p1, p) == 1):
            if not pow(g, (p-1)//p2, p) == 1:
                return g


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


def generate_keys(key_size=256, i_confidence=32):

    p = get_prime(key_size, i_confidence)
    g = find_primitive_root(p)
    g = pow(g, 2, p)
    x = random.randint(1, (p - 1) // 2)
    h = pow(g, x, p)

    public_key = PublicKey(p, g, h, key_size)
    private_key = PrivateKey(p, g, x, key_size)

    return {'private_key': private_key, 'public_key': public_key}


def encrypt(key: PublicKey, plaintext: string) -> string:
    z = encode(plaintext, key.key_size)

    cipher_pairs = []

    for i in z:

        y = random.randint(0, key.p)
        c = pow(key.g, y, key.p)

        d = (i*pow(key.h, y, key.p)) % key.p

        cipher_pairs.append([c, d])

    encrypted_str = ""
    for pair in cipher_pairs:
        encrypted_str += str(pair[0]) + ' ' + str(pair[1]) + ' '

    return encrypted_str


def decrypt(key: PrivateKey, cipher: string) -> string:

    plaintext = []

    cipherArray = cipher.split()
    if (not len(cipherArray) % 2 == 0):
        return "Malformed Cipher Text"
    for i in range(0, len(cipherArray), 2):

        c = int(cipherArray[i])

        d = int(cipherArray[i+1])

        s = pow(c, key.x, key.p)

        plain = (d*pow(s, key.p-2, key.p)) % key.p

        plaintext.append(plain)

    decryptedText = decode(plaintext, key.key_size)

    decryptedText = "".join([ch for ch in decryptedText if ch != '\x00'])

    return decryptedText


def sign(plaintext: string, priv: PrivateKey) -> string:
    sig_pairs = []
    x = encode(plaintext, priv.key_size)

    for i in x:
        while (1):
            k = random.randint(1, priv.p-2)
            if gcd(k, priv.p-1) == 1:
                break
        gamma = pow(priv.g, k, priv.p)
        l = get_inv_mul(k, priv.p-1)
        delta = ((i-priv.x*gamma)*l) % (priv.p-1)
        sig_pairs.append([gamma, delta])
    signature_str = ""
    for pair in sig_pairs:
        signature_str += str(pair[0]) + ' ' + str(pair[1]) + ' '
    return signature_str


def verify(plaintext: string, signature: string, pub: PublicKey) -> bool:
    x = encode(plaintext, pub.key_size)
    plaintext = []
    sign_array = signature.split()
    if (not len(sign_array) % 2 == 0):
        return False
    countMessageArray = 0
    for i in range(0, len(sign_array), 2):
        gamma = int(sign_array[i])

        delta = int(sign_array[i+1])

        leftBracket = (pow(pub.h, gamma, pub.p) *
                       pow(gamma, delta, pub.p)) % pub.p
        rightBracket = pow(pub.g, x[countMessageArray], pub.p)
        if (leftBracket != rightBracket):
            return False
        countMessageArray += 1

    return True


def test():
    keys = generate_keys(2048)
    priv = keys['private_key']
    print("This is the private key :x= ", priv.x)
    pub = keys['public_key']
    print("This is the public key: g=", pub.g, f"\nh=", pub.h, f"\nq=", pub.p)
    message = "My name is Nam and this is some garbage padding added to test"
    print("The message is as follows:")
    print(message)
    print(f"\t------------------------")
    cipher = encrypt(pub, message)
    print("The cipher is as follows:")
    print(cipher)
    print(f"\t------------------------")

    plain = decrypt(priv, cipher)

    print("The decrypted plaintext is as follows:")
    print(plain)
    print(f"\t------------------------")
    signature = sign(message, priv)
    print("The signature is as follows:")
    print(signature)
    print(f"\t------------------------")
    if verify(message, signature, pub):
        print("Signature is authentic")


test()
