Alice and Bob own a shared bank account, and, unfortunately, Bob cannot remember the four-digit PIN to access the account. Alice wants to help her partner Bob and send him the PIN via an insecure network.

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

Assume the adversary got hold of:

IV = 15304484387517434811
c = 0xa75da6155e61662665dfdec2264097b460cea3eb09c84461b5f728d9b0058361

The protocol run used SHA-256 as the hash function. The IV is encoded as a 8 byte big-endian integer; the date is ASCII encoded in a "YYYY-MM-DD" format. 
Recover the plaintext PIN and give the shared secret date. 