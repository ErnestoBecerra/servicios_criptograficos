import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding

import sys

from text_catalog import txt_practica0 as cat

BASE = '16'

def print_private_key_numbers(private_key):
    # Get the private numbers from the private key
    private_numbers = private_key.private_numbers()

    # Print the numbers in red, base 36
    print('\033[31m')
    print("Private Key Numbers:")
    print(f"d: {private_numbers.d}\n")
    print(f"n: {private_numbers.public_numbers.n}\n")
    print(f"p: {private_numbers.p}\n")
    print(f"q: {private_numbers.q}")
    print('\033[0m')

def print_public_key_numbers(public_key):
    # Get the public numbers from the public key
    public_numbers = public_key.public_numbers()

    # Print the numbers in cyan, base 36
    print('\033[36m')
    print("Public Key Numbers:")
    print(f"e: {public_numbers.e}\n")
    print(f"n: {public_numbers.n}")
    print('\033[0m')


# exponente publico sugerido por rfc
# https://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537
# https://www.ietf.org/rfc/rfc4871.txt
def generate_and_write_keys():
    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=cat.rsa.bits,
        backend=default_backend()
    )

    # Derive the public key
    public_key = private_key.public_key()

    # Write the public key to a file in the format of (e, n)
    with open(cat.rsa.pubname, "w") as f:
        f.write(f"{public_key.public_numbers().e}\n")
        f.write(f"{public_key.public_numbers().n}")

    # Write the private key to a file in the format of (d, n, p, q)
    with open(cat.rsa.privname, "w") as f:
        f.write(f"{private_key.private_numbers().d}\n")
        f.write(f"{private_key.private_numbers().public_numbers.n}\n")
        f.write(f"{private_key.private_numbers().p}\n")
        f.write(f"{private_key.private_numbers().q}")

    return public_key, private_key

def load_private(public_key):
    # Load the private key from the file
    public_numbers = public_key.public_numbers()
    with open(cat.rsa.privname, "r") as f:
        d = int(f.readline())
        n = int(f.readline())
        p = int(f.readline())
        q = int(f.readline())
    dmp1 = rsa.rsa_crt_dmp1(d, p)
    dmq1 = rsa.rsa_crt_dmq1(d, q)
    iqmp = rsa.rsa_crt_iqmp(p, q)
    private_numbers = rsa.RSAPrivateNumbers(p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, public_numbers=public_numbers)
    private_key = private_numbers.private_key(default_backend())
    return private_key

def load_public():
    with open(cat.rsa.pubname, "r") as f:
        e = int(f.readline())
        n = int(f.readline())
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(default_backend())
    public_key.public_numbers()
    return public_key

def load_keys():
    public_key = load_public()
    return public_key, load_private(public_key)

def encrypt_w_private(message_int:int, private_key):
    private_numbers = private_key.private_numbers()
    return pow(message_int, private_numbers.d, private_numbers.public_numbers.n)

def decrypt_w_public(cipher_int:int, public_key):
    public_numbers = public_key.public_numbers()
    return pow(cipher_int, public_numbers.e, public_numbers.n)

# Call the function
if __name__ == '__main__':
    if len(sys.argv) == 3:
        os.chdir(os.path.join(os.getcwd(), sys.argv[2]))
        if sys.argv[1] == '--keys':
            public_key, private_key = generate_and_write_keys()
            print_public_key_numbers(public_key)
            print_private_key_numbers(private_key)
            exit(f'Generado con exito claves rsa de {sys.argv[2]}')
        elif sys.argv[1] == '--load':
            public_key, private_key = load_keys()
            print_public_key_numbers(public_key)
            print_private_key_numbers(private_key)

            message = b'hola_mundo'
            message_int = int.from_bytes(message, byteorder='little')
            private_numbers = private_key.private_numbers()
            cipher_int = pow(message_int, private_numbers.d, private_numbers.public_numbers.n)

            print(message_int, '\n')
            print(cipher_int, '\n')

            public_numbers = public_key.public_numbers()
            deciphered_int = pow(cipher_int, public_numbers.e, public_numbers.n)

            print(deciphered_int)

            # message = b'Hello world'

            # signature = private_key.sign(
            #     message,
            #     padding.PSS(
            #         mgf=padding.MGF1(hashes.SHA256()),
            #         salt_length=padding.PSS.MAX_LENGTH
            #     ),
            #     hashes.SHA512()
            # )

            # signature = int.from_bytes(signature, 'big')
            # print(signature)



        else:
            exit('Uso: python rsa-keys.py <--keys> <Alice | Bob>')
    else:
        exit('Uso: python rsa-keys.py <--keys | --loads> <Alice | Bob>')