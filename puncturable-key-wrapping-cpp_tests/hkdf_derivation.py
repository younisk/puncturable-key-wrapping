from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives import hashes

# for pprf construction test

right = b"r"
left = b"l"

evals = [right, left, left, right, left, left]
derived = b"\x00" * 16
for eval in evals:
    derived = hkdf.HKDF(hashes.SHA256(), 16, salt=None, info=eval).derive(derived)

print('\\x'.join('{:02x}'.format(x) for x in derived))