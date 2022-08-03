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
