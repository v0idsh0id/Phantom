#!/usr/bin/env python3
"""
Simple examples of using the Phantom Cryptographic System
"""

from phantom_crypto import PhantomCryptoSystem

def example_basic():
    """Basic encryption and decryption"""
    print("=" * 60)
    print("Example 1: Basic Encryption/Decryption")
    print("=" * 60)
    
    # Create crypto system with a password
    crypto = PhantomCryptoSystem(b"my_secure_password_123")
    
    # Encrypt a message
    message = b"This is a secret message!"
    encrypted = crypto.encrypt(message)
    
    print(f"Original message: {message.decode()}")
    print(f"Encrypted (first 32 bytes): {encrypted['ciphertext'][:32].hex()}")
    print(f"Nonce: {encrypted['nonce'].hex()}")
    print(f"Salt: {encrypted['salt'].hex()}")
    print()
    
    # Create receiver with same password and salt
    receiver = PhantomCryptoSystem(b"my_secure_password_123", encrypted['salt'])
    
    # Decrypt the message
    decrypted = receiver.decrypt(encrypted['ciphertext'], encrypted['nonce'])
    print(f"Decrypted message: {decrypted.decode()}")
    print(f"✓ Success! Messages match: {message == decrypted}")
    print()


def example_multiple_messages():
    """Encrypting multiple messages with sequence numbers"""
    print("=" * 60)
    print("Example 2: Multiple Messages with Sequence Numbers")
    print("=" * 60)
    
    crypto = PhantomCryptoSystem(b"another_password")
    
    messages = [
        b"First message",
        b"Second message",
        b"Third message"
    ]
    
    encrypted_messages = []
    for i, msg in enumerate(messages):
        enc = crypto.encrypt(msg)
        encrypted_messages.append(enc)
        print(f"Message {i+1} encrypted, sequence: {enc['sequence']}")
    
    print()
    
    # Decrypt in order
    receiver = PhantomCryptoSystem(b"another_password", encrypted_messages[0]['salt'])
    
    for i, enc in enumerate(encrypted_messages):
        dec = receiver.decrypt(enc['ciphertext'], enc['nonce'], enc['sequence'])
        print(f"Message {i+1} decrypted: {dec.decode()}")
    
    print("✓ All messages decrypted successfully!")
    print()


def example_tamper_detection():
    """Demonstrating tamper detection"""
    print("=" * 60)
    print("Example 3: Tamper Detection")
    print("=" * 60)
    
    crypto = PhantomCryptoSystem(b"password123")
    
    message = b"Important data"
    encrypted = crypto.encrypt(message)
    
    print(f"Original message: {message.decode()}")
    print(f"Encrypted successfully")
    print()
    
    # Try to tamper with the ciphertext
    tampered_ciphertext = bytearray(encrypted['ciphertext'])
    tampered_ciphertext[-1] ^= 0x01  # Flip one bit
    
    receiver = PhantomCryptoSystem(b"password123", encrypted['salt'])
    
    print("Attempting to decrypt tampered ciphertext...")
    try:
        receiver.decrypt(bytes(tampered_ciphertext), encrypted['nonce'])
        print("ERROR: Tampering was not detected!")
    except ValueError as e:
        print(f"✓ Tampering detected: {e}")
    
    print()


def example_replay_resistance():
    """Demonstrating replay resistance"""
    print("=" * 60)
    print("Example 4: Replay Attack Prevention")
    print("=" * 60)
    
    crypto = PhantomCryptoSystem(b"secure_password")
    
    message = b"Transaction: Transfer $1000"
    encrypted = crypto.encrypt(message)
    
    print(f"Message: {message.decode()}")
    print(f"Sequence number: {encrypted['sequence']}")
    print()
    
    receiver = PhantomCryptoSystem(b"secure_password", encrypted['salt'])
    
    # First decryption succeeds
    decrypted = receiver.decrypt(
        encrypted['ciphertext'],
        encrypted['nonce'],
        encrypted['sequence']
    )
    print(f"First decryption: {decrypted.decode()}")
    print("✓ Success")
    print()
    
    # Try to replay with wrong sequence number
    print("Attempting replay attack with wrong sequence number...")
    try:
        receiver.decrypt(
            encrypted['ciphertext'],
            encrypted['nonce'],
            sequence=999  # Wrong sequence
        )
        print("ERROR: Replay attack was not detected!")
    except ValueError as e:
        print(f"✓ Replay attack detected: {e}")
    
    print()


def example_wrong_password():
    """Demonstrating that wrong password fails"""
    print("=" * 60)
    print("Example 5: Wrong Password Detection")
    print("=" * 60)
    
    crypto = PhantomCryptoSystem(b"correct_password")
    
    message = b"Confidential information"
    encrypted = crypto.encrypt(message)
    
    print(f"Message encrypted with correct password")
    print()
    
    # Try to decrypt with wrong password
    wrong_crypto = PhantomCryptoSystem(b"wrong_password", encrypted['salt'])
    
    print("Attempting to decrypt with wrong password...")
    try:
        wrong_crypto.decrypt(encrypted['ciphertext'], encrypted['nonce'])
        print("ERROR: Wrong password was accepted!")
    except ValueError as e:
        print(f"✓ Wrong password detected: {e}")
    
    print()


def main():
    """Run all examples"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "PHANTOM CRYPTOGRAPHIC SYSTEM" + " " * 20 + "║")
    print("║" + " " * 18 + "Usage Examples" + " " * 26 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    example_basic()
    example_multiple_messages()
    example_tamper_detection()
    example_replay_resistance()
    example_wrong_password()
    
    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)
    print()
    print("For more information, see:")
    print("  - README.md: Quick start and overview")
    print("  - ARCHITECTURE.md: Detailed design documentation")
    print("  - phantom_crypto.py: Implementation with inline comments")
    print()


if __name__ == "__main__":
    main()
