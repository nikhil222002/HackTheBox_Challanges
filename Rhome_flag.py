# Server Code

"""
from Crypto.Util.number import isPrime, long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randint
from hashlib import sha256

from secret import FLAG

class DH:

    def __init__(self):
        self.gen_params()

    def gen_params(self):
        self.r = getPrime(512)

        while True:
            self.q = getPrime(42)
            self.p = (2 * self.q * self.r) + 1
            if isPrime(self.p):
                break

        while True:
            self.h = getPrime(42)
            self.g = pow(self.h, 2 * self.r, self.p)
            if self.g != 1:
                break

        self.a = randint(2, self.p - 2)
        self.b = randint(2, self.p - 2)

        self.A, self.B = pow(self.g, self.a, self.p), pow(self.g, self.b, self.p)
        self.ss = pow(self.A, self.b, self.p)

    def encrypt(self, flag_part):
        key = sha256(long_to_bytes(self.ss)).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag_part, 16)).hex()
        return f"encrypted = {ct}"

    def get_params(self):
        return f"p = {self.p}\ng = {self.g}\nA = {self.A}\nB = {self.B}"

def menu():
    print("\nChoose as you please\n")
    print("1. Get parameters")
    print("2. Reset parameters!! This can take some time")
    print("3. Get Flag")

    option = input("\n> ")
    return option

def main():
    dh = DH()

    while True:
        choice = int(menu())
        if choice == 1:
            print(dh.get_params())
        elif choice == 2:
            dh.gen_params()
        elif choice == 3:
            print(dh.encrypt(FLAG))
        else:
            print('See you later.')
            exit(1)

if __name__ == "__main__":
    main()
"""

# FLAG Code

from sympy.ntheory import discrete_log
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Using option 1 get all the parameters from the server and store them in respective variables
p = 44400251423428643113883693008905732204438102678404384855088227662323448545643230003419339995772141348938523395295737832806253364530949419536119288651144103257837121823
g = 43178233283512049781915633196128547106246375048884115020229048961940407842476332540805934108251920120503653376315348326750430575471796484969394885686383566369201203887
A = 1744956382765782741435713063152320875597276559642312116617552123724790503643094972173041530857191493624037346028101744681905368024384957305557334261682564356947613428
B = 3260557793840436694108170269367877312413411605411322274875695483156194310774153173242307275220010301188270489265967338234281579642869249361892777064033290433314931446

try:
    a = discrete_log(p, A, g)
    print(f"Private key a: {a}") # Using  discrete log technique to get the private key a
except ValueError:
    print("Failed to find private key a.")
    exit()


ss = pow(B, a, p)   # Using the private key, calculate the shared secret
print(f"Shared secret (ss): {ss}")


key = sha256(long_to_bytes(ss)).digest()[:16] # Get the key using the shared secret's first 16 bytes and then print the key in hex format
print(f"AES Key: {key.hex()}")


encrypted_flag_hex = "e6e2d116c0941429ebaa81e55485529ac8d0bec2ef23bd197d54952196749b4a"  # Get encrypted flag from server in hex format and convert it to bytes
encrypted_flag = bytes.fromhex(encrypted_flag_hex)

cipher = AES.new(key, AES.MODE_ECB) # Finally, Decrypt the flag using the same ECB mode encryption used during encryption to get the flag
decrypted_flag = unpad(cipher.decrypt(encrypted_flag), 16)  # Unpad the encrypted flag to get data in fuxed size 16 byte blocks
print(f"Flag successfully retrieved: {decrypted_flag.decode()}")
