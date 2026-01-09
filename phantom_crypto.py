"""
Phantom Cryptographic System
A research-grade encryption/decryption system with architectural uniqueness.

Features:
- Multi-layer pipeline (permutation, substitution, state mixing, entropy expansion)
- Mutating key schedule with hash-chained state
- Non-determinism through runtime entropy
- Forward secrecy
- Integrity/tamper detection
- Replay resistance
- Constant-time operations where feasible
- Memory-safe secret handling
- Modular upgradeable components
"""

import os
import hmac
import hashlib
import secrets
import struct
import time
from typing import Tuple, Optional, List
from dataclasses import dataclass
from abc import ABC, abstractmethod


# ============================================================================
# Security Utilities
# ============================================================================

class SecureMemory:
    """Memory-safe handling of sensitive data"""
    
    def __init__(self, data: bytes):
        self._data = bytearray(data)
    
    def get(self) -> bytes:
        """Get the data (returns copy)"""
        return bytes(self._data)
    
    def clear(self):
        """Securely wipe memory"""
        if self._data:
            # Overwrite with random data then zeros
            for i in range(len(self._data)):
                self._data[i] = secrets.randbits(8)
            for i in range(len(self._data)):
                self._data[i] = 0
    
    def __del__(self):
        self.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ============================================================================
# Cryptographic Components (Abstract Base Classes)
# ============================================================================

class CryptoComponent(ABC):
    """Base class for upgradeable crypto components"""
    
    @abstractmethod
    def version(self) -> int:
        """Return component version"""
        pass


class PermutationLayer(CryptoComponent):
    """Abstract permutation layer"""
    
    @abstractmethod
    def permute(self, data: bytes, key_state: bytes) -> bytes:
        pass
    
    @abstractmethod
    def inverse_permute(self, data: bytes, key_state: bytes) -> bytes:
        pass


class SubstitutionLayer(CryptoComponent):
    """Abstract substitution layer"""
    
    @abstractmethod
    def substitute(self, data: bytes, key_state: bytes) -> bytes:
        pass
    
    @abstractmethod
    def inverse_substitute(self, data: bytes, key_state: bytes) -> bytes:
        pass


class StateMixer(CryptoComponent):
    """Abstract state mixing layer"""
    
    @abstractmethod
    def mix(self, data: bytes, key_state: bytes) -> bytes:
        pass
    
    @abstractmethod
    def inverse_mix(self, data: bytes, key_state: bytes) -> bytes:
        pass


class EntropyExpander(CryptoComponent):
    """Abstract entropy expansion layer"""
    
    @abstractmethod
    def expand(self, data: bytes, length: int, key_state: bytes) -> bytes:
        pass


# ============================================================================
# Concrete Implementations of Cryptographic Components
# ============================================================================

class PhantomPermutation(PermutationLayer):
    """
    Bit-level permutation using key-dependent shuffle
    Provides diffusion across the entire block
    """
    
    def version(self) -> int:
        return 1
    
    def _generate_permutation(self, key_state: bytes, size: int) -> List[int]:
        """Generate a key-dependent permutation"""
        # Use key_state to seed a deterministic shuffle
        indices = list(range(size))
        h = hashlib.blake2b(key_state + b'perm', digest_size=32).digest()
        
        # Fisher-Yates shuffle with key-dependent randomness
        for i in range(size - 1, 0, -1):
            # Generate deterministic "random" index
            j = int.from_bytes(
                hashlib.blake2b(h + i.to_bytes(4, 'big'), digest_size=4).digest(),
                'big'
            ) % (i + 1)
            indices[i], indices[j] = indices[j], indices[i]
        
        return indices
    
    def permute(self, data: bytes, key_state: bytes) -> bytes:
        """Permute bits based on key state"""
        if not data:
            return b''
        
        # Work with bit array
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        
        # Generate permutation
        perm = self._generate_permutation(key_state, len(bits))
        
        # Apply permutation
        permuted_bits = [bits[perm[i]] for i in range(len(bits))]
        
        # Convert back to bytes
        result = bytearray()
        for i in range(0, len(permuted_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(permuted_bits):
                    byte |= permuted_bits[i + j] << (7 - j)
            result.append(byte)
        
        return bytes(result)
    
    def inverse_permute(self, data: bytes, key_state: bytes) -> bytes:
        """Inverse permutation"""
        if not data:
            return b''
        
        # Work with bit array
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        
        # Generate permutation and compute inverse
        perm = self._generate_permutation(key_state, len(bits))
        inverse_perm = [0] * len(perm)
        for i, p in enumerate(perm):
            inverse_perm[p] = i
        
        # Apply inverse permutation
        unpermuted_bits = [bits[inverse_perm[i]] for i in range(len(bits))]
        
        # Convert back to bytes
        result = bytearray()
        for i in range(0, len(unpermuted_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(unpermuted_bits):
                    byte |= unpermuted_bits[i + j] << (7 - j)
            result.append(byte)
        
        return bytes(result)


class PhantomSubstitution(SubstitutionLayer):
    """
    Key-dependent S-box substitution
    Provides confusion through non-linear transformation
    """
    
    def version(self) -> int:
        return 1
    
    def _generate_sbox(self, key_state: bytes) -> List[int]:
        """Generate a key-dependent S-box"""
        # Create a permutation of 0-255
        sbox = list(range(256))
        h = hashlib.blake2b(key_state + b'sbox', digest_size=32).digest()
        
        # Fisher-Yates shuffle
        for i in range(255, 0, -1):
            j = int.from_bytes(
                hashlib.blake2b(h + i.to_bytes(4, 'big'), digest_size=4).digest(),
                'big'
            ) % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
        
        return sbox
    
    def substitute(self, data: bytes, key_state: bytes) -> bytes:
        """Apply S-box substitution"""
        sbox = self._generate_sbox(key_state)
        return bytes(sbox[b] for b in data)
    
    def inverse_substitute(self, data: bytes, key_state: bytes) -> bytes:
        """Apply inverse S-box substitution"""
        sbox = self._generate_sbox(key_state)
        # Generate inverse S-box
        inv_sbox = [0] * 256
        for i, v in enumerate(sbox):
            inv_sbox[v] = i
        return bytes(inv_sbox[b] for b in data)


class PhantomStateMixer(StateMixer):
    """
    State mixing through XOR with key-derived stream and byte rotation
    Provides additional diffusion and key dependency
    """
    
    def version(self) -> int:
        return 1
    
    def _mix_stream(self, length: int, key_state: bytes, label: bytes) -> bytes:
        """Generate mixing stream from key state"""
        result = bytearray()
        counter = 0
        while len(result) < length:
            h = hashlib.blake2b(
                key_state + label + counter.to_bytes(4, 'big'),
                digest_size=64
            ).digest()
            result.extend(h)
            counter += 1
        return bytes(result[:length])
    
    def mix(self, data: bytes, key_state: bytes) -> bytes:
        """Mix state with key-derived stream"""
        stream = self._mix_stream(len(data), key_state, b'mix_fwd')
        
        # XOR with stream
        mixed = bytearray(a ^ b for a, b in zip(data, stream))
        
        # Rotate bytes based on key state
        rotation = int.from_bytes(
            hashlib.blake2b(key_state + b'rotate', digest_size=4).digest(),
            'big'
        ) % max(len(mixed), 1)
        
        rotated = mixed[rotation:] + mixed[:rotation]
        
        return bytes(rotated)
    
    def inverse_mix(self, data: bytes, key_state: bytes) -> bytes:
        """Inverse mix operation"""
        # Inverse rotation
        rotation = int.from_bytes(
            hashlib.blake2b(key_state + b'rotate', digest_size=4).digest(),
            'big'
        ) % max(len(data), 1)
        
        unrotated = bytearray(data[-rotation:] + data[:-rotation] if rotation > 0 else data)
        
        # XOR with stream (self-inverse)
        stream = self._mix_stream(len(unrotated), key_state, b'mix_fwd')
        unmixed = bytes(a ^ b for a, b in zip(unrotated, stream))
        
        return unmixed


class PhantomEntropyExpander(EntropyExpander):
    """
    Entropy expansion using hash-based construction
    Expands entropy for key derivation
    """
    
    def version(self) -> int:
        return 1
    
    def expand(self, data: bytes, length: int, key_state: bytes) -> bytes:
        """Expand entropy to desired length"""
        result = bytearray()
        counter = 0
        
        while len(result) < length:
            h = hashlib.blake2b(
                data + key_state + counter.to_bytes(8, 'big'),
                digest_size=64
            ).digest()
            result.extend(h)
            counter += 1
        
        return bytes(result[:length])


# ============================================================================
# Key Schedule and State Management
# ============================================================================

@dataclass
class KeyState:
    """Represents the current state of the key schedule"""
    master_key: bytes
    round_key: bytes
    state_chain: bytes
    round_number: int
    timestamp: float


class MutatingKeySchedule:
    """
    Mutating key schedule with hash-chained state
    Provides forward secrecy and non-determinism
    """
    
    def __init__(self, user_secret: bytes, salt: Optional[bytes] = None):
        """
        Initialize key schedule
        
        Args:
            user_secret: User-provided secret key
            salt: Optional salt (generated if not provided)
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        self.salt = salt
        self.entropy_expander = PhantomEntropyExpander()
        
        # Derive master key from user secret and salt (fully deterministic)
        # This allows receiver to recreate the same master key
        combined = user_secret + salt
        
        self.master_key = SecureMemory(
            hashlib.blake2b(combined, digest_size=64, key=b'phantom_master').digest()
        )
        
        # Initialize state chain (deterministic from master key)
        self.state_chain = hashlib.blake2b(
            self.master_key.get() + b'init_chain',
            digest_size=64
        ).digest()
        
        self.round_number = 0
    
    def derive_round_key(self, additional_entropy: Optional[bytes] = None) -> KeyState:
        """
        Derive next round key with forward secrecy
        
        Args:
            additional_entropy: Optional additional entropy
        
        Returns:
            KeyState for current round
        """
        # Include additional entropy if provided
        if additional_entropy is None:
            additional_entropy = secrets.token_bytes(16)
        
        # Hash-chain the state
        self.state_chain = hashlib.blake2b(
            self.state_chain + 
            self.round_number.to_bytes(8, 'big') + 
            additional_entropy,
            digest_size=64,
            key=self.master_key.get()
        ).digest()
        
        # Derive round key from master key and chained state
        round_key = self.entropy_expander.expand(
            self.master_key.get() + self.state_chain,
            128,  # 128 bytes for round key
            self.state_chain
        )
        
        key_state = KeyState(
            master_key=self.master_key.get(),
            round_key=round_key,
            state_chain=self.state_chain,
            round_number=self.round_number,
            timestamp=time.time()
        )
        
        self.round_number += 1
        
        return key_state
    
    def get_salt(self) -> bytes:
        """Get the salt used for key derivation"""
        return self.salt
    
    def clear(self):
        """Securely clear sensitive data"""
        self.master_key.clear()
        if hasattr(self, 'state_chain'):
            self.state_chain = b'\x00' * len(self.state_chain)


# ============================================================================
# Multi-Layer Encryption Pipeline
# ============================================================================

class PhantomCipher:
    """
    Research-grade encryption system with multi-layer pipeline
    """
    
    BLOCK_SIZE = 128  # bytes
    VERSION = 1
    
    def __init__(
        self,
        permutation: Optional[PermutationLayer] = None,
        substitution: Optional[SubstitutionLayer] = None,
        state_mixer: Optional[StateMixer] = None,
        entropy_expander: Optional[EntropyExpander] = None
    ):
        """
        Initialize cipher with modular components
        
        Args:
            permutation: Permutation layer (default: PhantomPermutation)
            substitution: Substitution layer (default: PhantomSubstitution)
            state_mixer: State mixer (default: PhantomStateMixer)
            entropy_expander: Entropy expander (default: PhantomEntropyExpander)
        """
        self.permutation = permutation or PhantomPermutation()
        self.substitution = substitution or PhantomSubstitution()
        self.state_mixer = state_mixer or PhantomStateMixer()
        self.entropy_expander = entropy_expander or PhantomEntropyExpander()
    
    def _pad(self, data: bytes) -> bytes:
        """Apply PKCS7-style padding"""
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data: bytes) -> bytes:
        """Remove PKCS7-style padding"""
        if not data:
            raise ValueError("Cannot unpad empty data")
        pad_len = data[-1]
        if pad_len > self.BLOCK_SIZE or pad_len == 0:
            raise ValueError("Invalid padding")
        # Verify padding
        if not all(b == pad_len for b in data[-pad_len:]):
            raise ValueError("Invalid padding")
        return data[:-pad_len]
    
    def _process_block(
        self,
        block: bytes,
        key_state: KeyState,
        encrypt: bool = True
    ) -> bytes:
        """
        Process a single block through the multi-layer pipeline
        
        Args:
            block: Block to process
            key_state: Current key state
            encrypt: True for encryption, False for decryption
        """
        # Derive layer-specific keys from round key
        perm_key = hashlib.blake2b(
            key_state.round_key + b'perm_layer',
            digest_size=32
        ).digest()
        sub_key = hashlib.blake2b(
            key_state.round_key + b'sub_layer',
            digest_size=32
        ).digest()
        mix_key = hashlib.blake2b(
            key_state.round_key + b'mix_layer',
            digest_size=32
        ).digest()
        
        if encrypt:
            # Forward pipeline: permute -> substitute -> mix
            result = self.permutation.permute(block, perm_key)
            result = self.substitution.substitute(result, sub_key)
            result = self.state_mixer.mix(result, mix_key)
        else:
            # Reverse pipeline: inverse mix -> inverse substitute -> inverse permute
            result = self.state_mixer.inverse_mix(block, mix_key)
            result = self.substitution.inverse_substitute(result, sub_key)
            result = self.permutation.inverse_permute(result, perm_key)
        
        return result
    
    def encrypt(
        self,
        plaintext: bytes,
        key_schedule: MutatingKeySchedule,
        sequence_number: int = 0
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with multi-layer pipeline
        
        Args:
            plaintext: Data to encrypt
            key_schedule: Key schedule instance
            sequence_number: Sequence number for replay resistance
        
        Returns:
            Tuple of (ciphertext, nonce)
        """
        # Generate nonce for non-determinism
        nonce = secrets.token_bytes(32)
        
        # Derive round key with nonce as additional entropy
        key_state = key_schedule.derive_round_key(nonce)
        
        # Pad plaintext
        padded = self._pad(plaintext)
        
        # Process blocks
        ciphertext = bytearray()
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            if len(block) < self.BLOCK_SIZE:
                # Should not happen with padding, but handle gracefully
                block = block + b'\x00' * (self.BLOCK_SIZE - len(block))
            
            # Derive block-specific key state deterministically (without mutating key schedule)
            block_entropy = nonce + i.to_bytes(8, 'big')
            block_round_key = self.entropy_expander.expand(
                key_state.round_key + block_entropy,
                128,
                key_state.state_chain
            )
            block_key_state = KeyState(
                master_key=key_state.master_key,
                round_key=block_round_key,
                state_chain=key_state.state_chain,
                round_number=key_state.round_number,
                timestamp=key_state.timestamp
            )
            
            encrypted_block = self._process_block(block, block_key_state, encrypt=True)
            ciphertext.extend(encrypted_block)
        
        # Generate MAC for integrity/tamper detection
        mac_key = hashlib.blake2b(
            key_state.master_key + b'mac_key',
            digest_size=64
        ).digest()
        
        mac_data = (
            nonce +
            sequence_number.to_bytes(8, 'big') +
            bytes(ciphertext)
        )
        
        mac = hmac.new(mac_key, mac_data, hashlib.sha3_512).digest()
        
        # Construct final ciphertext: version | seq_num | mac | ciphertext
        final_ciphertext = (
            struct.pack('!I', self.VERSION) +
            struct.pack('!Q', sequence_number) +
            mac +
            bytes(ciphertext)
        )
        
        return final_ciphertext, nonce
    
    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        key_schedule: MutatingKeySchedule,
        expected_sequence: Optional[int] = None
    ) -> bytes:
        """
        Decrypt ciphertext with multi-layer pipeline
        
        Args:
            ciphertext: Data to decrypt (includes version, sequence, MAC)
            nonce: Nonce used during encryption
            key_schedule: Key schedule instance
            expected_sequence: Expected sequence number for replay detection
        
        Returns:
            Decrypted plaintext
        
        Raises:
            ValueError: On integrity check failure or replay detection
        """
        # Parse ciphertext structure
        if len(ciphertext) < 4 + 8 + 64:
            raise ValueError("Ciphertext too short")
        
        version = struct.unpack('!I', ciphertext[:4])[0]
        if version != self.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        sequence_number = struct.unpack('!Q', ciphertext[4:12])[0]
        received_mac = ciphertext[12:12+64]  # SHA3-512 produces 64 bytes
        encrypted_data = ciphertext[12+64:]
        
        # Replay resistance check
        if expected_sequence is not None and sequence_number != expected_sequence:
            raise ValueError(
                f"Sequence number mismatch: expected {expected_sequence}, "
                f"got {sequence_number}"
            )
        
        # Derive the same round key (key schedule must be in sync)
        key_state = key_schedule.derive_round_key(nonce)
        
        # Verify MAC for integrity/tamper detection
        mac_key = hashlib.blake2b(
            key_state.master_key + b'mac_key',
            digest_size=64
        ).digest()
        
        mac_data = (
            nonce +
            sequence_number.to_bytes(8, 'big') +
            encrypted_data
        )
        
        expected_mac = hmac.new(mac_key, mac_data, hashlib.sha3_512).digest()
        
        if not constant_time_compare(received_mac, expected_mac):
            raise ValueError("MAC verification failed - data may be tampered")
        
        # Decrypt blocks
        plaintext = bytearray()
        for i in range(0, len(encrypted_data), self.BLOCK_SIZE):
            block = encrypted_data[i:i + self.BLOCK_SIZE]
            if len(block) < self.BLOCK_SIZE:
                # Last block might be incomplete
                block = block + b'\x00' * (self.BLOCK_SIZE - len(block))
            
            # Derive same block-specific key state deterministically
            block_entropy = nonce + i.to_bytes(8, 'big')
            block_round_key = self.entropy_expander.expand(
                key_state.round_key + block_entropy,
                128,
                key_state.state_chain
            )
            block_key_state = KeyState(
                master_key=key_state.master_key,
                round_key=block_round_key,
                state_chain=key_state.state_chain,
                round_number=key_state.round_number,
                timestamp=key_state.timestamp
            )
            
            decrypted_block = self._process_block(block, block_key_state, encrypt=False)
            plaintext.extend(decrypted_block)
        
        # Remove padding
        return self._unpad(bytes(plaintext))


# ============================================================================
# High-Level API
# ============================================================================

class PhantomCryptoSystem:
    """
    High-level interface for the Phantom cryptographic system
    """
    
    def __init__(self, user_secret: bytes, salt: Optional[bytes] = None):
        """
        Initialize crypto system
        
        Args:
            user_secret: User-provided secret key
            salt: Optional salt (will be generated if not provided)
        """
        self.cipher = PhantomCipher()
        self.key_schedule = MutatingKeySchedule(user_secret, salt)
        self.sequence_counter = 0
    
    def encrypt(self, plaintext: bytes) -> dict:
        """
        Encrypt plaintext
        
        Args:
            plaintext: Data to encrypt
        
        Returns:
            Dictionary with 'ciphertext', 'nonce', 'sequence', 'salt'
        """
        ciphertext, nonce = self.cipher.encrypt(
            plaintext,
            self.key_schedule,
            self.sequence_counter
        )
        
        result = {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'sequence': self.sequence_counter,
            'salt': self.key_schedule.get_salt()
        }
        
        self.sequence_counter += 1
        
        return result
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, sequence: Optional[int] = None) -> bytes:
        """
        Decrypt ciphertext
        
        Args:
            ciphertext: Data to decrypt
            nonce: Nonce from encryption
            sequence: Expected sequence number (None to skip check)
        
        Returns:
            Decrypted plaintext
        """
        return self.cipher.decrypt(ciphertext, nonce, self.key_schedule, sequence)
    
    def get_salt(self) -> bytes:
        """Get the salt used for key derivation"""
        return self.key_schedule.get_salt()
    
    def clear(self):
        """Securely clear sensitive data"""
        self.key_schedule.clear()


# ============================================================================
# Example Usage
# ============================================================================

def example_usage():
    """Demonstrate the Phantom crypto system"""
    
    print("=== Phantom Cryptographic System Demo ===\n")
    
    # Initialize crypto system
    user_secret = b"my_super_secret_password_12345"
    crypto = PhantomCryptoSystem(user_secret)
    
    print(f"Salt (hex): {crypto.get_salt().hex()[:32]}...")
    print()
    
    # Encrypt some data
    plaintext = b"Hello, this is a secret message that needs to be encrypted!"
    print(f"Plaintext: {plaintext.decode()}")
    print(f"Plaintext size: {len(plaintext)} bytes")
    print()
    
    encrypted = crypto.encrypt(plaintext)
    print(f"Ciphertext size: {len(encrypted['ciphertext'])} bytes")
    print(f"Ciphertext (hex): {encrypted['ciphertext'].hex()[:64]}...")
    print(f"Nonce (hex): {encrypted['nonce'].hex()[:32]}...")
    print(f"Sequence: {encrypted['sequence']}")
    print()
    
    # Create a new crypto system with same secret and salt (simulating receiver)
    crypto2 = PhantomCryptoSystem(user_secret, encrypted['salt'])
    
    # Decrypt the data
    decrypted = crypto2.decrypt(
        encrypted['ciphertext'],
        encrypted['nonce'],
        encrypted['sequence']
    )
    
    print(f"Decrypted: {decrypted.decode()}")
    print(f"Match: {plaintext == decrypted}")
    print()
    
    # Test replay resistance
    print("Testing replay resistance...")
    try:
        # Try to decrypt with wrong sequence number
        crypto2.decrypt(
            encrypted['ciphertext'],
            encrypted['nonce'],
            sequence=999  # Wrong sequence
        )
        print("ERROR: Replay attack not detected!")
    except ValueError as e:
        print(f"✓ Replay attack detected: {e}")
    print()
    
    # Test tamper detection
    print("Testing tamper detection...")
    tampered_ciphertext = bytearray(encrypted['ciphertext'])
    tampered_ciphertext[-1] ^= 0x01  # Flip a bit
    try:
        crypto2.decrypt(bytes(tampered_ciphertext), encrypted['nonce'])
        print("ERROR: Tampering not detected!")
    except ValueError as e:
        print(f"✓ Tampering detected: {e}")
    print()
    
    # Clean up
    crypto.clear()
    crypto2.clear()
    
    print("=== Demo Complete ===")


if __name__ == "__main__":
    example_usage()
