import secrets

def generate_rc4_key(key_length):
    # Generate a secure random key of the specified length
    return secrets.token_bytes(key_length)

# Define the desired key length in bytes (e.g., 16 bytes for a 128-bit key)
key_length = 16

# Generate an RC4 key
rc4_key = generate_rc4_key(key_length)

# Print the generated key in hexadecimal format
print(rc4_key.hex())

