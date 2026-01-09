# Phantom Cryptographic System Architecture

## Overview

Phantom is a research-grade encryption/decryption system with a unique, non-standard architecture. It is designed for educational and research purposes to demonstrate advanced cryptographic concepts beyond traditional AES/RSA/ECC systems.

## Design Philosophy

The system emphasizes:
- **Architectural Uniqueness**: Custom-designed primitives instead of standard algorithms
- **Confusion and Diffusion**: Multi-layer pipeline ensuring thorough data transformation
- **Forward Secrecy**: Hash-chained key state prevents recovery of old keys
- **Non-determinism**: Runtime entropy ensures different ciphertexts for identical plaintexts
- **Integrity Protection**: MAC-based tamper detection
- **Replay Resistance**: Sequence number validation
- **Constant-time Operations**: Where feasible to prevent timing attacks
- **Memory Safety**: Secure handling and wiping of sensitive data
- **Modularity**: Upgradeable components for long-term maintainability

## Multi-Layer Pipeline

The encryption pipeline consists of four main transformations applied sequentially:

### 1. Permutation Layer (`PhantomPermutation`)

**Purpose**: Provides diffusion by rearranging bits across the entire block.

**Implementation**:
- Operates at the bit level for maximum diffusion
- Uses key-dependent Fisher-Yates shuffle for permutation generation
- Permutation is deterministic given the same key state
- Invertible for decryption

**Security Properties**:
- Each bit position depends on the key
- Small changes in position create large cascading effects
- Provides initial diffusion across block boundaries

### 2. Substitution Layer (`PhantomSubstitution`)

**Purpose**: Provides confusion through non-linear byte-level transformations.

**Implementation**:
- Key-dependent S-box generation (256-byte lookup table)
- Each byte is independently substituted
- Uses Fisher-Yates shuffle to create permutation of 0-255
- Invertible through inverse S-box computation

**Security Properties**:
- Non-linear transformation breaks linear relationships
- Key-dependent S-boxes prevent precomputation attacks
- Each S-box is a complete permutation (bijective)

### 3. State Mixing Layer (`PhantomStateMixer`)

**Purpose**: Additional diffusion and key-dependent transformation.

**Implementation**:
- XOR with key-derived pseudo-random stream
- Byte rotation based on key state
- Both operations are self-inverse or easily invertible

**Security Properties**:
- Introduces additional key dependence
- XOR provides fast, constant-time mixing
- Rotation spreads changes across block boundaries

### 4. Entropy Expansion (`PhantomEntropyExpander`)

**Purpose**: Expand limited entropy into arbitrary-length pseudo-random streams.

**Implementation**:
- BLAKE2b-based construction
- Counter-mode generation for arbitrary lengths
- Deterministic given same inputs

**Security Properties**:
- Based on cryptographically secure hash function
- Collision resistance from BLAKE2b
- Suitable for key derivation and stream generation

## Key Schedule and State Management

### Master Key Derivation

```
master_key = BLAKE2b(user_secret || salt, key="phantom_master")
```

**Properties**:
- Deterministic given same secret and salt
- Salt prevents rainbow table attacks
- 512-bit (64-byte) master key
- Stored in secure memory with wiping on cleanup

### Mutating Key Schedule

The key schedule implements forward secrecy through hash-chaining:

```
state_chain[n+1] = BLAKE2b(
    state_chain[n] || round_number || nonce,
    key=master_key
)

round_key = EntropyExpand(master_key || state_chain, 128 bytes)
```

**Properties**:
- Each round produces a unique key
- Cannot derive previous keys from current state (forward secrecy)
- Nonce provides per-message non-determinism
- Round counter prevents replay within same session

### Per-Block Key Derivation

Each block gets its own key variation:

```
block_key = EntropyExpand(
    round_key || nonce || block_index,
    128 bytes
)
```

**Properties**:
- Different keys for each block
- Deterministic for decryption
- Block index prevents block reordering attacks

## Encryption Process

```
1. Generate random nonce (32 bytes)
2. Derive round key from key schedule + nonce
3. Pad plaintext (PKCS#7)
4. For each block:
   a. Derive block-specific key
   b. Apply permutation layer
   c. Apply substitution layer
   d. Apply state mixing layer
5. Generate MAC over (nonce || sequence || ciphertext)
6. Return: version || sequence || MAC || ciphertext, nonce
```

## Decryption Process

```
1. Parse: version || sequence || MAC || ciphertext
2. Verify version compatibility
3. Check sequence number (replay resistance)
4. Derive same round key using provided nonce
5. Verify MAC (integrity/tamper detection)
6. For each block:
   a. Derive same block-specific key
   b. Apply inverse state mixing
   c. Apply inverse substitution
   d. Apply inverse permutation
7. Remove padding
8. Return plaintext
```

## Security Features

### Non-determinism

- Random nonce per message (32 bytes)
- Included in key derivation
- Ensures different ciphertexts for identical plaintexts
- Prevents pattern analysis

### Forward Secrecy

- Hash-chained state prevents backward derivation
- Old messages cannot be decrypted even if current state is compromised
- Requires compromise of specific message's key state

### Integrity and Tamper Detection

- HMAC-SHA3-512 over entire ciphertext
- Includes nonce and sequence number
- Verified before decryption
- Constant-time comparison prevents timing attacks

### Replay Resistance

- Sequence numbers included in MAC
- Optionally verified during decryption
- Prevents replay of old valid messages
- Application must track expected sequence

### Constant-time Operations

- MAC comparison uses constant-time algorithm
- XOR operations are naturally constant-time
- Lookup tables (S-boxes) may leak through cache timing
  - Acceptable for research/educational use
  - Production systems should use cache-timing-resistant S-boxes

### Memory Safety

- `SecureMemory` class for sensitive data
- Overwrites with random data then zeros on cleanup
- Context manager support for automatic cleanup
- Wipes master key and intermediate states

## Modularity and Upgradeability

### Component-Based Architecture

All cryptographic primitives inherit from base classes:
- `PermutationLayer`
- `SubstitutionLayer`
- `StateMixer`
- `EntropyExpander`
- `CryptoComponent` (base class with versioning)

### Upgrading Components

```python
# Custom implementations can be injected
class MyCustomPermutation(PermutationLayer):
    def version(self) -> int:
        return 2
    # ... implement permute() and inverse_permute()

cipher = PhantomCipher(
    permutation=MyCustomPermutation(),
    # other components use defaults
)
```

### Version Management

- Each component reports its version
- Ciphertext includes version field
- Future versions can maintain backward compatibility
- Decryptor can select appropriate component based on version

## Block Structure

### Ciphertext Format

```
+--------+----------+----------+------------------+
| 4 bytes| 8 bytes  | 64 bytes | Variable         |
| Version| Sequence | MAC      | Encrypted blocks |
+--------+----------+----------+------------------+
```

### Block Size

- 128 bytes per block
- Larger than traditional block ciphers (AES: 16 bytes)
- Allows for more complex transformations
- PKCS#7 padding for last block

## Performance Characteristics

### Time Complexity

- **Permutation**: O(n) where n = block_size × 8 (bits)
- **Substitution**: O(n) where n = block_size (bytes)
- **State Mixing**: O(n) for XOR and rotation
- **Overall Encryption**: O(m × b) where m = message size, b = block operations

### Space Complexity

- **Key State**: 256 bytes (master + round + chain)
- **S-box Generation**: 256 bytes per block
- **Permutation**: O(block_size × 8) for bit array
- **Working Memory**: O(block_size) for intermediate transformations

### Throughput

- **Slower than AES**: Educational design prioritizes clarity over speed
- **Suitable for**: Small to medium messages (< 1 MB)
- **Not Optimized for**: High-throughput applications

## Use Cases

### ✅ Appropriate Use Cases

- Educational cryptography demonstrations
- Research into custom cipher design
- Security training and CTF challenges
- Prototyping novel cryptographic concepts
- Non-critical data protection with unique requirements

### ❌ Inappropriate Use Cases

- Production systems requiring proven security
- High-performance applications
- Compliance with regulatory standards (FIPS, etc.)
- Critical infrastructure protection
- Financial or medical data protection

## Security Considerations

### Strengths

1. **Layered Defense**: Multiple transformation layers
2. **Key Dependency**: All layers depend on secret key
3. **Integrity Protection**: MAC prevents undetected tampering
4. **Forward Secrecy**: Old keys unrecoverable
5. **Non-determinism**: Prevents pattern analysis

### Limitations

1. **Unproven Security**: No formal security proofs
2. **Limited Cryptanalysis**: Not subjected to extensive public review
3. **Cache Timing**: S-box lookups may leak information
4. **Performance**: Slower than optimized standard algorithms
5. **Key Management**: Requires secure key distribution (as with all symmetric systems)

### Comparison with Standard Algorithms

| Feature | Phantom | AES-GCM | ChaCha20-Poly1305 |
|---------|---------|---------|-------------------|
| Block Size | 128 bytes | 16 bytes | Stream cipher |
| Speed | Slow | Very Fast | Fast |
| Security Proof | No | Yes | Yes |
| Standardized | No | Yes (NIST) | Yes (RFC) |
| Unique Design | Yes | No | No |
| Modularity | High | Low | Medium |
| Research Value | High | Low | Medium |
| Production Ready | No | Yes | Yes |

## Testing and Validation

The system includes comprehensive tests covering:

1. **Unit Tests**: Each component tested independently
2. **Integration Tests**: Full encrypt/decrypt cycles
3. **Security Tests**: 
   - Tamper detection
   - Replay resistance
   - Key sensitivity
   - Avalanche effect (bit diffusion)
4. **Edge Cases**:
   - Empty messages
   - Large messages
   - Multiple messages
5. **Component Modularity**: Custom component injection

## Future Enhancements

Potential improvements for future versions:

1. **Constant-time S-boxes**: Bitsliced implementation
2. **Parallel Processing**: Multi-threaded block processing
3. **Hardware Acceleration**: SIMD optimizations
4. **Formal Verification**: Machine-checked security proofs
5. **Key Exchange Protocol**: Diffie-Hellman integration
6. **Asymmetric Support**: Public-key layer
7. **Streaming API**: Process data without buffering
8. **Compression**: Pre-encryption compression
9. **Multiple Rounds**: Configurable transformation rounds
10. **Side-channel Resistance**: Power analysis protection

## References

### Cryptographic Concepts

- **Confusion and Diffusion**: Shannon, C. (1949). "Communication Theory of Secrecy Systems"
- **BLAKE2**: Aumasson et al. (2013). "BLAKE2: simpler, smaller, fast as MD5"
- **Forward Secrecy**: Diffie, van Oorschot, Wiener (1992). "Authentication and Authenticated Key Exchanges"
- **Constant-time Programming**: Bernstein (2005). "Cache-timing attacks on AES"

### Design Inspiration

- **Rijndael/AES**: Substitution-Permutation Network structure
- **Serpent**: Multiple rounds of simple operations
- **Keccak/SHA-3**: Sponge construction concepts
- **Signal Protocol**: Forward secrecy and ratcheting

## Conclusion

Phantom demonstrates that custom cryptographic primitives can be composed into a complete encryption system. While not suitable for production use, it serves as an excellent educational tool for understanding:

- How encryption systems work internally
- The importance of multiple security layers
- Key management and forward secrecy
- Integrity protection and authentication
- The design decisions behind cryptographic systems

For production use, always prefer well-studied, standardized algorithms like AES-GCM or ChaCha20-Poly1305.
