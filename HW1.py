import math
import numpy as np

# Padding symbol added to ciphertext when name length is odd
PAD_CHAR = '$'
# Numeric value of padding character ("x" → 23)
PAD_NUM = ord('x') - ord('a')
MOD = 26   # Alphabet size for ℤ26 arithmetic

# ================== CORE CIPHER FUNCTIONS ==================

def NameCipher_encryption(name1, name2, key, a=None, b=None):
    # Normalize both names to lowercase
    name1 = name1.lower()
    name2 = name2.lower()

    # Convert keys from 4-letter strings into 2×2 matrices
    key1 = key_to_matrix(key[0])
    key2 = key_to_matrix(key[1])

    # Keys must be invertible modulo 26
    if not is_valid_key(key1) or not is_valid_key(key2):
        raise Exception("Invalid key")

    # Compute a and b from the first letters of the plaintext names
    a_val = to_num(name1[0])
    b_val = to_num(name2[0])

    # Encrypt both names
    ciphertext1, ciphertext2 = NameCipher_encrypt_two_names(name1, name2, key1, key2, a_val, b_val)
    return ciphertext1, ciphertext2


def NameCipher_decryption(c1, c2, key, a_char, b_char):
    # Convert keys
    key1 = key_to_matrix(key[0])
    key2 = key_to_matrix(key[1])

    # Check for padding markers and record them
    c1_was_padded = c1.endswith(PAD_CHAR)
    c2_was_padded = c2.endswith(PAD_CHAR)

    # Remove padding markers before processing
    if c1.endswith(PAD_CHAR):
        c1 = c1[:-1]
    if c2.endswith(PAD_CHAR):
        c2 = c2[:-1]

    # Convert ciphertext characters → numeric vectors
    vec1 = name_to_vector(c1)
    vec2 = name_to_vector(c2)

    # Split into 2×1 blocks
    blocks1 = split_into_blocks_decrypt(vec1)
    blocks2 = split_into_blocks_decrypt(vec2)

    # Recompute a and b (in ℤ26)
    a = to_num(a_char.lower())
    b = to_num(b_char.lower())

    # Decrypt each block
    plain1 = [decrypt_block(block, key1, key2, a, b) for block in blocks1]
    plain2 = [decrypt_block(block, key1, key2, a, b) for block in blocks2]

    # Flatten back to a single list
    flat1 = np.concatenate(plain1)
    flat2 = np.concatenate(plain2)

    # Convert numbers → letters
    text1 = vector_to_name(flat1)
    text2 = vector_to_name(flat2)

    # If padding existed originally, remove the extra 'x'
    if c1_was_padded:
        text1 = text1[:-1]
    if c2_was_padded:
        text2 = text2[:-1]

    return text1, text2



def NameCipher_iterative_attack(name1, name2, key):
    # Use fixed a,b from the original names
    a_num = to_num(name1[0].lower())
    b_num = to_num(name2[0].lower())

    # First encryption (start of cycle)
    c1, c2 = NameCipher_encryption(name1, name2, key)
    print(f"Initial ciphertext: {c1} {c2}")

    # Remove padding markers for consistency in cycle detection
    s1 = c1[:-1] if c1.endswith(PAD_CHAR) else c1
    s2 = c2[:-1] if c2.endswith(PAD_CHAR) else c2

    # Store cycle start
    start1, start2 = s1, s2

    iterations = 0

    # Repeatedly encrypt ciphertext until cycle returns to start
    while True:
        n1, n2 = NameCipher_encryption(s1, s2, key, a=a_num, b=b_num)

        # Remove padding again
        s1 = n1[:-1] if n1.endswith(PAD_CHAR) else n1
        s2 = n2[:-1] if n2.endswith(PAD_CHAR) else n2

        iterations += 1

        # Cycle completed
        if s1 == start1 and s2 == start2:
            print("\n===== ITERATIVE ATTACK RESULT =====")
            print(f"Original plaintext:  {name1} {name2}")
            print(f"Final ciphertext:    {c1} {c2}")
            print(f"Full cycle length:   {iterations}")
            print("===================================")
            return s1, s2




def decrypt_block(block, key1, key2, a, b):
    # (a,b) shift vector
    ab = np.array([a, b])

    # Compute inverse matrices of K1 and K2
    inv1 = inverse_matrix(key1)
    inv2 = inverse_matrix(key2)

    # Undo second encryption step: (Z − (a,b)) K2^{-1}
    block1 = (block - ab) % 26
    block1 = block1 @ inv2 % 26

    # Undo first step: (Y − (a,b)) K1^{-1}
    block0 = (block1 - ab) % 26
    block0 = block0 @ inv1 % 26

    return block0.astype(int).reshape(2,)


def split_into_blocks_decrypt(vec):
    # Split vector into blocks of size 2
    return [vec[i:i+2] for i in range(0, len(vec), 2)]


def inverse_matrix(matrix):
    # Compute the modular inverse of a 2×2 matrix over ℤ26
    a, b = matrix[0]
    c, d = matrix[1]
    det = (a * d - b * c) % 26
    det_inv = pow(int(det), -1, 26)

    return np.array([
        [(d * det_inv) % 26, (-b * det_inv) % 26],
        [(-c * det_inv) % 26, (a * det_inv) % 26]
    ], dtype=int)


def name_to_vector(name):
    # Convert characters → numeric values in 0..25
    return np.array([to_num(c) for c in name])


def vector_to_name(vector):
    # Convert numeric values → letters
    return ''.join(to_char(int(n)) for n in vector)


def array_to_text(array):
    # Convert array of numeric blocks → ciphertext string
    text = ''
    for n in array:
        text += vector_to_name(n)
    return text


def NameCipher_encrypt_one(name, key1, key2, a, b):
    # Convert characters → numeric values
    vec = name_to_vector(name)

    # Split plaintext into 2×1 blocks
    blocks, needs_padding = split_into_blocks(vec)

    # First stage encryption: X K1 + (a,b)
    stage1 = np.array([encrypt(block, a, b, key1) for block in blocks])

    # Second stage encryption: Y K2 + (a,b)
    stage2 = np.array([encrypt(block, a, b, key2) for block in stage1])

    return stage2, needs_padding


def split_into_blocks(vec):
    # If plaintext length is odd, append padding ('x')
    needs_padding = (len(vec) % 2 == 1)

    if needs_padding:
        vec = np.append(vec, PAD_NUM)

    # Split into pairs
    blocks = [vec[i:i+2] for i in range(0, len(vec), 2)]
    return blocks, needs_padding


def NameCipher_encrypt_two_names(name1, name2, key1, key2, a, b):
    # Encrypt name1
    c1, pad1 = NameCipher_encrypt_one(name1, key1, key2, a, b)
    # Encrypt name2
    c2, pad2 = NameCipher_encrypt_one(name2, key1, key2, a, b)

    # Convert numeric blocks → text
    text1 = array_to_text(c1)
    text2 = array_to_text(c2)

    # Add padding marker if necessary
    if pad1:
        text1 += PAD_CHAR
    if pad2:
        text2 += PAD_CHAR

    return text1, text2


def encrypt(block, a, b, key):
    # Compute X·K + (a,b) modulo 26
    extra = np.array([a, b])
    return (vector_and_matrix_multiply(block, key) + extra) % 26


def vector_and_matrix_multiply(a, b):
    # Standard matrix multiplication
    return a @ b


def key_to_matrix(key):
    # Convert 4-letter key → 2×2 matrix in numeric form
    nums = [to_num(c) for c in key]
    return np.array(nums).reshape(2, 2)


def to_num(c):
    # Map 'a'..'z' → 0..25
    return ord(c) - ord('a')


def to_char(n):
    # Map 0..25 → 'a'..'z'
    return chr(n % 26 + ord('a'))


def is_valid_key(key):
    # Check if determinant is invertible modulo 26
    det = determinant(key)
    return math.gcd(det, 26) == 1


def determinant(key):
    # Compute det(K) mod 26
    a, b = key[0][0], key[0][1]
    c, d = key[1][0], key[1][1]
    return (a * d - b * c) % 26


def verify_key_print(key_str):
    """
    Display full verification steps (as required in Exercise 1.1).
    """
    print("\n--- Verifying key:", key_str, "---")

    nums = [to_num(c) for c in key_str]
    print(f"Numeric values: {nums}")

    # Key matrix
    matrix = np.array(nums).reshape(2, 2)
    print("Matrix form:\n", matrix)

    # Determinant computation
    a, b, c, d = nums
    det = (a * d - b * c) % 26
    print(f"Determinant: ({a}*{d} - {b}*{c}) mod 26 = {det}")

    # GCD(det, 26)
    g = math.gcd(det, 26)
    print("gcd(det, 26) =", g)

    if g != 1:
        print("❌ INVALID KEY (det not invertible mod 26)\n")
    else:
        print("✅ VALID KEY (matrix invertible mod 26)\n")

    return g == 1


def is_valid_key_matrix(K: np.ndarray) -> bool:
    """
    Fully verify a matrix:
    - shape must be 2×2
    - entries must be integers 0..25
    - determinant invertible mod 26
    """
    if K.ndim != 2 or K.shape[0] != K.shape[1]:
        return False

    if not np.issubdtype(K.dtype, np.integer):
        return False
    if np.any(K < 0) or np.any(K >= MOD):
        return False

    det = round(np.linalg.det(K))
    det_mod = det % MOD
    return math.gcd(det_mod, MOD) == 1

# ================== MAIN ==================

def main():
    print("=== NameCipher Program ===")

    print("\n=== Key Verification ===")

    # Predefined keys for the homework
    key = ["road", "door"]

    # Display validation steps (Exercise 1.1 requirement)
    verify_key_print(key[0])
    verify_key_print(key[1])

    # Additional internal validation
    K1, K2 = key_to_matrix(key[0]), key_to_matrix(key[1])

    if not is_valid_key_matrix(K1):
        raise ValueError("ERROR: K1 is NOT a valid key matrix")

    if not is_valid_key_matrix(K2):
        raise ValueError("ERROR: K2 is NOT a valid key matrix")

    print("Keys are valid! You can encrypt now.\n")

    # Ask user for names
    name1 = input("Enter first name: ").strip()
    name2 = input("Enter second name: ").strip()

    print("\n--- Encrypting ---")
    c1, c2 = NameCipher_encryption(name1, name2, key)
    print(f"Ciphertext 1: {c1}")
    print(f"Ciphertext 2: {c2}")

    print("\n--- Decrypting ---")
    p1, p2 = NameCipher_decryption(c1, c2, key, name1[0], name2[0])
    print(f"Decrypted Name 1: {p1}")
    print(f"Decrypted Name 2: {p2}")

    print("\n--- Iterative Attack ---")
    NameCipher_iterative_attack(name1, name2, key)


if __name__ == "__main__":
    main()