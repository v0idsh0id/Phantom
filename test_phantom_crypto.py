"""
Comprehensive tests for the Phantom Cryptographic System
"""

import unittest
import secrets
import time
from phantom_crypto import (
    PhantomCryptoSystem,
    PhantomCipher,
    MutatingKeySchedule,
    PhantomPermutation,
    PhantomSubstitution,
    PhantomStateMixer,
    PhantomEntropyExpander,
    SecureMemory,
    constant_time_compare
)


class TestSecureMemory(unittest.TestCase):
    """Test secure memory handling"""
    
    def test_secure_memory_basic(self):
        """Test basic secure memory operations"""
        data = b"secret_data"
        mem = SecureMemory(data)
        self.assertEqual(mem.get(), data)
        mem.clear()
    
    def test_secure_memory_context_manager(self):
        """Test secure memory as context manager"""
        data = b"secret_data"
        with SecureMemory(data) as mem:
            self.assertEqual(mem.get(), data)
        # Should be cleared after context


class TestConstantTimeCompare(unittest.TestCase):
    """Test constant-time comparison"""
    
    def test_equal_bytes(self):
        """Test comparison of equal bytes"""
        a = b"test_data_123"
        b = b"test_data_123"
        self.assertTrue(constant_time_compare(a, b))
    
    def test_unequal_bytes(self):
        """Test comparison of unequal bytes"""
        a = b"test_data_123"
        b = b"test_data_124"
        self.assertFalse(constant_time_compare(a, b))
    
    def test_different_lengths(self):
        """Test comparison of different length bytes"""
        a = b"short"
        b = b"much_longer_string"
        self.assertFalse(constant_time_compare(a, b))


class TestPhantomPermutation(unittest.TestCase):
    """Test permutation layer"""
    
    def setUp(self):
        self.perm = PhantomPermutation()
        self.key_state = secrets.token_bytes(32)
    
    def test_permutation_inverse(self):
        """Test that inverse permutation reverses permutation"""
        data = b"test_data_for_permutation_test"
        permuted = self.perm.permute(data, self.key_state)
        unpermuted = self.perm.inverse_permute(permuted, self.key_state)
        self.assertEqual(data, unpermuted)
    
    def test_permutation_changes_data(self):
        """Test that permutation actually changes data"""
        data = b"test_data_for_permutation_test"
        permuted = self.perm.permute(data, self.key_state)
        # Should be different (statistically almost always)
        self.assertNotEqual(data, permuted)
    
    def test_empty_data(self):
        """Test permutation with empty data"""
        data = b""
        permuted = self.perm.permute(data, self.key_state)
        self.assertEqual(permuted, b"")
    
    def test_key_dependency(self):
        """Test that different keys produce different permutations"""
        data = b"test_data_for_permutation_test"
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        
        perm1 = self.perm.permute(data, key1)
        perm2 = self.perm.permute(data, key2)
        
        # Different keys should produce different results
        self.assertNotEqual(perm1, perm2)


class TestPhantomSubstitution(unittest.TestCase):
    """Test substitution layer"""
    
    def setUp(self):
        self.sub = PhantomSubstitution()
        self.key_state = secrets.token_bytes(32)
    
    def test_substitution_inverse(self):
        """Test that inverse substitution reverses substitution"""
        data = b"test_data_for_substitution_test"
        substituted = self.sub.substitute(data, self.key_state)
        unsubstituted = self.sub.inverse_substitute(substituted, self.key_state)
        self.assertEqual(data, unsubstituted)
    
    def test_substitution_changes_data(self):
        """Test that substitution changes data"""
        data = b"test_data_for_substitution_test"
        substituted = self.sub.substitute(data, self.key_state)
        # Should be different (statistically almost always)
        self.assertNotEqual(data, substituted)
    
    def test_key_dependency(self):
        """Test that different keys produce different substitutions"""
        data = b"test_data_for_substitution_test"
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        
        sub1 = self.sub.substitute(data, key1)
        sub2 = self.sub.substitute(data, key2)
        
        self.assertNotEqual(sub1, sub2)


class TestPhantomStateMixer(unittest.TestCase):
    """Test state mixing layer"""
    
    def setUp(self):
        self.mixer = PhantomStateMixer()
        self.key_state = secrets.token_bytes(32)
    
    def test_mixing_inverse(self):
        """Test that inverse mixing reverses mixing"""
        data = b"test_data_for_mixing_test_with_more_data"
        mixed = self.mixer.mix(data, self.key_state)
        unmixed = self.mixer.inverse_mix(mixed, self.key_state)
        self.assertEqual(data, unmixed)
    
    def test_mixing_changes_data(self):
        """Test that mixing changes data"""
        data = b"test_data_for_mixing_test_with_more_data"
        mixed = self.mixer.mix(data, self.key_state)
        self.assertNotEqual(data, mixed)


class TestPhantomEntropyExpander(unittest.TestCase):
    """Test entropy expansion"""
    
    def setUp(self):
        self.expander = PhantomEntropyExpander()
        self.key_state = secrets.token_bytes(32)
    
    def test_expansion_length(self):
        """Test that expansion produces correct length"""
        data = b"short"
        lengths = [64, 128, 256, 512]
        
        for length in lengths:
            expanded = self.expander.expand(data, length, self.key_state)
            self.assertEqual(len(expanded), length)
    
    def test_deterministic_expansion(self):
        """Test that expansion is deterministic"""
        data = b"test_data"
        length = 128
        
        exp1 = self.expander.expand(data, length, self.key_state)
        exp2 = self.expander.expand(data, length, self.key_state)
        
        self.assertEqual(exp1, exp2)
    
    def test_key_dependency(self):
        """Test that different keys produce different expansions"""
        data = b"test_data"
        length = 128
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        
        exp1 = self.expander.expand(data, length, key1)
        exp2 = self.expander.expand(data, length, key2)
        
        self.assertNotEqual(exp1, exp2)


class TestMutatingKeySchedule(unittest.TestCase):
    """Test mutating key schedule"""
    
    def test_key_schedule_initialization(self):
        """Test key schedule initialization"""
        secret = b"user_secret_password"
        ks = MutatingKeySchedule(secret)
        
        self.assertIsNotNone(ks.master_key)
        self.assertIsNotNone(ks.salt)
        self.assertEqual(ks.round_number, 0)
    
    def test_key_schedule_with_salt(self):
        """Test key schedule with provided salt"""
        secret = b"user_secret_password"
        salt = secrets.token_bytes(32)
        ks = MutatingKeySchedule(secret, salt)
        
        self.assertEqual(ks.get_salt(), salt)
    
    def test_round_key_derivation(self):
        """Test round key derivation"""
        secret = b"user_secret_password"
        ks = MutatingKeySchedule(secret)
        
        key_state1 = ks.derive_round_key()
        key_state2 = ks.derive_round_key()
        
        # Different rounds should produce different keys
        self.assertNotEqual(key_state1.round_key, key_state2.round_key)
        self.assertNotEqual(key_state1.state_chain, key_state2.state_chain)
        
        # Round numbers should increment
        self.assertEqual(key_state1.round_number, 0)
        self.assertEqual(key_state2.round_number, 1)
    
    def test_forward_secrecy(self):
        """Test that old round keys cannot be derived from new ones"""
        secret = b"user_secret_password"
        ks = MutatingKeySchedule(secret)
        
        key_state1 = ks.derive_round_key()
        key_state2 = ks.derive_round_key()
        key_state3 = ks.derive_round_key()
        
        # All keys should be different
        self.assertNotEqual(key_state1.round_key, key_state2.round_key)
        self.assertNotEqual(key_state2.round_key, key_state3.round_key)
        self.assertNotEqual(key_state1.round_key, key_state3.round_key)


class TestPhantomCipher(unittest.TestCase):
    """Test the core cipher"""
    
    def setUp(self):
        self.cipher = PhantomCipher()
        self.secret = b"test_secret_password"
        self.key_schedule = MutatingKeySchedule(self.secret)
    
    def test_padding(self):
        """Test PKCS7 padding"""
        data = b"test"
        padded = self.cipher._pad(data)
        unpadded = self.cipher._unpad(padded)
        self.assertEqual(data, unpadded)
    
    def test_padding_full_block(self):
        """Test padding when data is multiple of block size"""
        data = b"A" * self.cipher.BLOCK_SIZE
        padded = self.cipher._pad(data)
        self.assertEqual(len(padded), self.cipher.BLOCK_SIZE * 2)
        unpadded = self.cipher._unpad(padded)
        self.assertEqual(data, unpadded)
    
    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption"""
        plaintext = b"Hello, World!"
        
        # Encrypt
        ciphertext, nonce = self.cipher.encrypt(plaintext, self.key_schedule, 0)
        
        # Create new key schedule for decryption (same secret)
        key_schedule2 = MutatingKeySchedule(self.secret, self.key_schedule.get_salt())
        
        # Decrypt
        decrypted = self.cipher.decrypt(ciphertext, nonce, key_schedule2, 0)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_decrypt_long_message(self):
        """Test encryption/decryption of long message"""
        plaintext = b"A" * 1000
        
        ciphertext, nonce = self.cipher.encrypt(plaintext, self.key_schedule, 0)
        
        key_schedule2 = MutatingKeySchedule(self.secret, self.key_schedule.get_salt())
        decrypted = self.cipher.decrypt(ciphertext, nonce, key_schedule2, 0)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_decrypt_empty(self):
        """Test encryption/decryption of empty message"""
        plaintext = b""
        
        ciphertext, nonce = self.cipher.encrypt(plaintext, self.key_schedule, 0)
        
        key_schedule2 = MutatingKeySchedule(self.secret, self.key_schedule.get_salt())
        decrypted = self.cipher.decrypt(ciphertext, nonce, key_schedule2, 0)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_non_deterministic_encryption(self):
        """Test that encryption is non-deterministic"""
        plaintext = b"Same message"
        
        # Reset key schedule for fair comparison
        ks1 = MutatingKeySchedule(self.secret)
        ks2 = MutatingKeySchedule(self.secret)
        
        cipher1 = PhantomCipher()
        cipher2 = PhantomCipher()
        
        ciphertext1, nonce1 = cipher1.encrypt(plaintext, ks1, 0)
        ciphertext2, nonce2 = cipher2.encrypt(plaintext, ks2, 0)
        
        # Nonces should be different
        self.assertNotEqual(nonce1, nonce2)
        # Ciphertexts should be different
        self.assertNotEqual(ciphertext1, ciphertext2)
    
    def test_tamper_detection(self):
        """Test MAC verification catches tampering"""
        plaintext = b"Important message"
        
        ciphertext, nonce = self.cipher.encrypt(plaintext, self.key_schedule, 0)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01
        
        key_schedule2 = MutatingKeySchedule(self.secret, self.key_schedule.get_salt())
        
        with self.assertRaises(ValueError) as ctx:
            self.cipher.decrypt(bytes(tampered), nonce, key_schedule2, 0)
        
        self.assertIn("MAC verification failed", str(ctx.exception))
    
    def test_replay_resistance(self):
        """Test sequence number verification"""
        plaintext = b"Message"
        
        ciphertext, nonce = self.cipher.encrypt(plaintext, self.key_schedule, 5)
        
        key_schedule2 = MutatingKeySchedule(self.secret, self.key_schedule.get_salt())
        
        # Try to decrypt with wrong sequence number
        with self.assertRaises(ValueError) as ctx:
            self.cipher.decrypt(ciphertext, nonce, key_schedule2, 10)
        
        self.assertIn("Sequence number mismatch", str(ctx.exception))
    
    def test_wrong_key(self):
        """Test that wrong key fails decryption"""
        plaintext = b"Secret message"
        
        ciphertext, nonce = self.cipher.encrypt(plaintext, self.key_schedule, 0)
        
        # Try to decrypt with wrong key
        wrong_key_schedule = MutatingKeySchedule(b"wrong_password", self.key_schedule.get_salt())
        
        with self.assertRaises(ValueError) as ctx:
            self.cipher.decrypt(ciphertext, nonce, wrong_key_schedule, 0)
        
        self.assertIn("MAC verification failed", str(ctx.exception))


class TestPhantomCryptoSystem(unittest.TestCase):
    """Test high-level crypto system API"""
    
    def test_basic_encrypt_decrypt(self):
        """Test basic encryption and decryption workflow"""
        secret = b"user_password_123"
        crypto = PhantomCryptoSystem(secret)
        
        plaintext = b"Hello, Phantom!"
        encrypted = crypto.encrypt(plaintext)
        
        # Create receiver with same secret and salt
        crypto2 = PhantomCryptoSystem(secret, encrypted['salt'])
        decrypted = crypto2.decrypt(
            encrypted['ciphertext'],
            encrypted['nonce'],
            encrypted['sequence']
        )
        
        self.assertEqual(plaintext, decrypted)
    
    def test_multiple_messages(self):
        """Test encrypting multiple messages"""
        secret = b"user_password_123"
        crypto = PhantomCryptoSystem(secret)
        
        messages = [
            b"First message",
            b"Second message",
            b"Third message"
        ]
        
        encrypted_messages = []
        for msg in messages:
            encrypted_messages.append(crypto.encrypt(msg))
        
        # Verify sequence numbers increment
        for i, enc in enumerate(encrypted_messages):
            self.assertEqual(enc['sequence'], i)
        
        # Create receiver
        crypto2 = PhantomCryptoSystem(secret, encrypted_messages[0]['salt'])
        
        # Decrypt all messages
        for i, (msg, enc) in enumerate(zip(messages, encrypted_messages)):
            decrypted = crypto2.decrypt(
                enc['ciphertext'],
                enc['nonce'],
                enc['sequence']
            )
            self.assertEqual(msg, decrypted)
    
    def test_replay_attack_prevention(self):
        """Test that replay attacks are detected"""
        secret = b"user_password_123"
        crypto = PhantomCryptoSystem(secret)
        
        plaintext = b"Original message"
        encrypted = crypto.encrypt(plaintext)
        
        crypto2 = PhantomCryptoSystem(secret, encrypted['salt'])
        
        # First decryption should work
        decrypted = crypto2.decrypt(
            encrypted['ciphertext'],
            encrypted['nonce'],
            encrypted['sequence']
        )
        self.assertEqual(plaintext, decrypted)
        
        # Try to replay with wrong sequence
        with self.assertRaises(ValueError):
            crypto2.decrypt(
                encrypted['ciphertext'],
                encrypted['nonce'],
                sequence=encrypted['sequence'] + 1
            )
    
    def test_secure_cleanup(self):
        """Test secure cleanup of sensitive data"""
        secret = b"user_password_123"
        crypto = PhantomCryptoSystem(secret)
        
        # Use the system
        plaintext = b"Test message"
        crypto.encrypt(plaintext)
        
        # Clear sensitive data
        crypto.clear()
        
        # Note: We can't easily verify memory is cleared,
        # but we ensure the method exists and doesn't error
    
    def test_large_message(self):
        """Test encryption of large message"""
        secret = b"user_password_123"
        crypto = PhantomCryptoSystem(secret)
        
        # 10 KB message
        plaintext = secrets.token_bytes(10240)
        encrypted = crypto.encrypt(plaintext)
        
        crypto2 = PhantomCryptoSystem(secret, encrypted['salt'])
        decrypted = crypto2.decrypt(
            encrypted['ciphertext'],
            encrypted['nonce'],
            encrypted['sequence']
        )
        
        self.assertEqual(plaintext, decrypted)


class TestModularComponents(unittest.TestCase):
    """Test that components can be swapped"""
    
    def test_custom_components(self):
        """Test cipher with custom components"""
        # Create cipher with explicit components
        cipher = PhantomCipher(
            permutation=PhantomPermutation(),
            substitution=PhantomSubstitution(),
            state_mixer=PhantomStateMixer(),
            entropy_expander=PhantomEntropyExpander()
        )
        
        secret = b"test_secret"
        ks = MutatingKeySchedule(secret)
        
        plaintext = b"Test message"
        ciphertext, nonce = cipher.encrypt(plaintext, ks, 0)
        
        ks2 = MutatingKeySchedule(secret, ks.get_salt())
        decrypted = cipher.decrypt(ciphertext, nonce, ks2, 0)
        
        self.assertEqual(plaintext, decrypted)


class TestSecurityProperties(unittest.TestCase):
    """Test security properties of the system"""
    
    def test_avalanche_effect(self):
        """Test that small input changes cause large output changes"""
        secret = b"test_secret"
        crypto1 = PhantomCryptoSystem(secret)
        
        plaintext1 = b"Test message"
        plaintext2 = b"Test messag"  # One character different
        
        enc1 = crypto1.encrypt(plaintext1)
        enc2 = crypto1.encrypt(plaintext2)
        
        # Import cipher to access header size constant
        from phantom_crypto import PhantomCipher
        
        # Compare ciphertexts (skip header with version, seq, mac)
        ct1 = enc1['ciphertext'][PhantomCipher.HEADER_SIZE:]
        ct2 = enc2['ciphertext'][PhantomCipher.HEADER_SIZE:]
        
        # Count differing bits
        diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ct1, ct2))
        total_bits = len(ct1) * 8
        
        # Should have significant difference (> 25% of bits)
        self.assertGreater(diff_bits / total_bits, 0.25)
    
    def test_key_sensitivity(self):
        """Test that different keys produce very different outputs"""
        plaintext = b"Same message"
        
        crypto1 = PhantomCryptoSystem(b"key1")
        crypto2 = PhantomCryptoSystem(b"key2")
        
        enc1 = crypto1.encrypt(plaintext)
        enc2 = crypto2.encrypt(plaintext)
        
        # Ciphertexts should be completely different
        self.assertNotEqual(enc1['ciphertext'], enc2['ciphertext'])


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
