"""
Alice and Bob own a shared bank account, and, unfortunately, Bob cannot remember the four-digit PIN to access the account.
Alice wants to help her partner Bob and send him the PIN via an insecure network.

They both know the date they first met (let's call it date) and consider it a shared secret value. 
They come up with the following protocol, where H is a cryptographic hash function with a 256-bit digest size, and z <-$Z returns a random integer z ∈ Z.

Let m <- "Our secret PIN code is: XXXX...." be the message Alice wants to send to Bob. The message is assumed to be ASCII encoded, representing each letter/digit as one byte.

Alice                                               Bob
――――――――――――――――――――――――――――――――――――――――――――――――――――――――
IV <- ${0, 1, ....., 2⁶⁴}
h <- H(IV || date)
c <-  m ⊕ h

                        IV, c
                    ――――――――――――――――>
                                    h <- H(IV || date)
                                    m <- c ⊕ h

The protocol essentially consists of a one-time pad encryption using h as key, which is of the same size as m. 
h is computed as the hash of a random number IV concatenated with the secret value date.

Q. Assume the adversary got hold of:

IV = 15304484387517434811
c = 0xa75da6155e61662665dfdec2264097b460cea3eb09c84461b5f728d9b0058361

The protocol run used SHA-256 as the hash function. The IV is encoded as a 8 byte big-endian integer; the date is ASCII encoded in a "YYYY-MM-DD" format. 
Recover the plaintext PIN and give the shared secret date. 

"""

import datetime
import hashlib

# Storing IV in Big Endian representation
IV = (15304484387517434811).to_bytes(8, byteorder="big")
c1 = 'a75da6155e61662665dfdec2264097b460cea3eb09c84461b5f728d9b0058361'
c = bytes.fromhex(c1)  # Convert cipher from hex to bytes


def byte_xor(ba1, ba2):
    return bytes([a ^ b for a, b in zip(ba1, ba2)])

# For date I assume the start date to be 1-1-1990 to today
# m = "Our secret PIN code is: XXXX...."


day_delta = datetime.timedelta(days=1)
start_date = datetime.date(1990, 1, 1)
end_date = datetime.date.today()

list1 = []

for i in range((end_date - start_date).days + 1):
    current_date = (start_date + i*day_delta)
    list1.append(current_date)

# Iterating through date:

for d in list1:
    date1 = str(d)
    date_bytes = date1.encode()  # Storing date in bytes
    concat = IV + date_bytes  # Concatenating IV with date
    hash = hashlib.sha256(concat)
    h = hash.digest()  # Storing hash in bytes
    m = byte_xor(c, h)

    # Comparing if the m matches the plaintext message and printing the corresponding date
    if m.startswith(b'Our'):
        print(m)
        print(d)
