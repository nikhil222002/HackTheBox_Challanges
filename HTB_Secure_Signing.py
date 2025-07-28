# Server Code

"""
def menu():
    print("1 - Sign Your Message")
    print("2 - Verify Your Message")
    print("3 - Exit")


def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])


def H(m):
    return sha256(m).digest()


def main():
    print(WELCOME_MSG)

    while True:
        try:
            menu()
            choice = int(input("> "))
        except:
            print("Try again.")
            continue

        if choice == 1:
            message = input("Enter your message: ").encode()
            hsh = H(xor(message, FLAG))
            print(f"Hash: {hsh.hex()}")
        elif choice == 2:
            message = input("Enter your message: ").encode()
            hsh = input("Enter your hash: ")
            if H(xor(message, FLAG)).hex() == hsh:
                print("[+] Signature Validated!\n")
            else:
                print(f"[!] Invalid Signature!\n")
        else:
            print("Good Bye")
            exit(0)


if __name__ == "__main__":
    main()
"""

# FLAG Code

from pwn import remote
from hashlib import sha256
from string import printable

def hash_SHA256(data):
    return sha256(data).hexdigest() # Function to calculate SHA-256 hash of the given data

def get_server_hash(data):
    server.sendlineafter(b'>', b'1') # Pass option 1 to server
    server.sendlineafter(b'message:', data) # Pass the data as the message to server
    response = server.recvline().decode().strip().split()[-1]  # Recieve the response and strip spaces and store the hash of the message in the response variable
    return response

def derive_flag():
    FLAG = []
    Printable_chars = "_" + printable.replace('_', '') # Create a list of all the printable ASCII Characters

    while True:
        current_length = len(FLAG) + 1
        reference = hash_SHA256(b"\x00" * current_length) # Create a reference hash with length equal to current flag length + 1

        potential_hashes = {
            char: get_server_hash("".join(FLAG).encode() + char.encode()) # Create a dictionary with all the characters and the hash from server after adding it to the FLAG flag
            for char in Printable_chars
        }

        match = next((char for char, h in potential_hashes.items() if h == reference), None) # See if any returned hash is equal to reference zero hash

        if match:
            FLAG.append(match)  # Append the new character to the FLAG list
            print(f"Found the Character: {match}")  # Print the new character
            if match == '}':  # If end of the flag is reached, break
                break
        else:
            print("Not a printable character.") # If no match is found, Print failed message and exit with code 1
            exit(1)

    return ''.join(FLAG)

# Server IP and Port Information
server = remote('83.136.254.158', 51810)

flag_result = derive_flag()
print(f"Flag successfully retrieved: {flag_result}")  # Print the final Flag
