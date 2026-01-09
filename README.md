# Phantom

A research-grade, architecturally unique encryption/decryption system designed for educational and research purposes.

## ⚠️ Important Notice

**This is a research and educational project.** It has not undergone the extensive cryptanalysis required for production use. For production systems, use well-established, proven algorithms like AES-GCM, ChaCha20-Poly1305, or other NIST-approved cryptographic standards.

## Features

- ✨ **Architecturally Unique**: Custom-designed primitives (no AES/RSA/ECC)
- 🔄 **Multi-Layer Pipeline**: Permutation → Substitution → State Mixing → Entropy Expansion
- 🔑 **Mutating Key Schedule**: Hash-chained state with forward secrecy
- 🎲 **Non-Deterministic**: Runtime entropy ensures unique ciphertexts
- 🛡️ **Integrity Protection**: HMAC-based tamper detection
- 🔒 **Replay Resistance**: Sequence number validation
- ⏱️ **Constant-Time Operations**: Where feasible (MAC verification)
- 🧹 **Memory-Safe**: Secure wiping of sensitive data
- 🧩 **Modular Design**: Upgradeable components

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/v0idsh0id/Phantom.git
cd Phantom

# No dependencies required - uses Python standard library only!
```

### Basic Usage

```python
from phantom_crypto import PhantomCryptoSystem

# Initialize with a secret key
crypto = PhantomCryptoSystem(b"my_secret_password")

# Encrypt a message
plaintext = b"Hello, World!"
encrypted = crypto.encrypt(plaintext)

print(f"Ciphertext: {encrypted['ciphertext'].hex()[:64]}...")
print(f"Nonce: {encrypted['nonce'].hex()}")
print(f"Sequence: {encrypted['sequence']}")

# To decrypt, receiver needs: secret, salt, ciphertext, nonce
receiver = PhantomCryptoSystem(b"my_secret_password", encrypted['salt'])
decrypted = receiver.decrypt(
    encrypted['ciphertext'],
    encrypted['nonce'],
    encrypted['sequence']  # Optional: for replay protection
)

print(f"Decrypted: {decrypted.decode()}")  # "Hello, World!"
```

### Running Tests

```bash
python test_phantom_crypto.py
```

### Running the Demo

```bash
python phantom_crypto.py
```

## Running on GitHub

You can run this program directly on GitHub using GitHub Actions! 

### Automated Testing

Every push and pull request automatically runs:
- ✅ Full test suite (38 tests)
- ✅ Demo execution
- ✅ Examples validation
- ✅ Multi-version Python testing (3.9, 3.10, 3.11, 3.12)

View test results in the **Actions** tab of the repository.

### Manual Execution

You can manually run the program on GitHub:

1. Go to the **Actions** tab in the repository
2. Select **"Run Examples"** workflow
3. Click **"Run workflow"**
4. Choose which examples to run:
   - **all**: Run both demo and examples
   - **demo**: Run the built-in demo only
   - **examples**: Run the comprehensive examples only
5. Click **"Run workflow"** button
6. View the output in the workflow run logs

This allows you to test the encryption system without installing anything locally!

### CI/CD Status

[![CI](https://github.com/v0idsh0id/Phantom/workflows/CI/badge.svg)](https://github.com/v0idsh0id/Phantom/actions/workflows/ci.yml)
[![Tests](https://github.com/v0idsh0id/Phantom/workflows/Tests/badge.svg)](https://github.com/v0idsh0id/Phantom/actions/workflows/test.yml)

## Architecture Overview

Phantom uses a multi-layer encryption pipeline:

```
┌─────────────┐
│  Plaintext  │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  Permutation    │  ← Bit-level rearrangement
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Substitution   │  ← Non-linear S-box transformation
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  State Mixing   │  ← XOR with key stream + rotation
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Ciphertext     │
└─────────────────┘
```

Each layer is:
- **Key-dependent**: Controlled by derived keys
- **Invertible**: Supports decryption
- **Modular**: Can be swapped with custom implementations

## Key Components

### 1. Cryptographic Layers

- **PhantomPermutation**: Bit-level permutation for diffusion
- **PhantomSubstitution**: Key-dependent S-boxes for confusion
- **PhantomStateMixer**: XOR mixing and byte rotation
- **PhantomEntropyExpander**: BLAKE2b-based key derivation

### 2. Key Management

- **MutatingKeySchedule**: Forward-secret key derivation
- **SecureMemory**: Safe handling of sensitive data
- **Hash-chained state**: Prevents recovery of old keys

### 3. Security Features

- **MAC Authentication**: HMAC-SHA3-512 for integrity
- **Replay Resistance**: Sequence number tracking
- **Non-determinism**: Random nonce per message
- **Constant-time Comparison**: Timing-attack resistant MAC verification

## Security Properties

| Property | Implementation |
|----------|----------------|
| **Confusion** | S-box substitution, key mixing |
| **Diffusion** | Bit permutation, state mixing |
| **Forward Secrecy** | Hash-chained key state |
| **Non-determinism** | Random nonce (32 bytes) |
| **Integrity** | HMAC-SHA3-512 MAC |
| **Replay Resistance** | Sequence numbers |
| **Memory Safety** | Secure wiping on cleanup |

## Advanced Usage

### Custom Components

```python
from phantom_crypto import PhantomCipher, PermutationLayer

class MyCustomPermutation(PermutationLayer):
    def version(self) -> int:
        return 2
    
    def permute(self, data: bytes, key_state: bytes) -> bytes:
        # Custom implementation
        pass
    
    def inverse_permute(self, data: bytes, key_state: bytes) -> bytes:
        # Custom inverse
        pass

# Use custom component
cipher = PhantomCipher(permutation=MyCustomPermutation())
```

### Multiple Messages

```python
crypto = PhantomCryptoSystem(b"secret")

messages = [b"First", b"Second", b"Third"]
encrypted_msgs = [crypto.encrypt(msg) for msg in messages]

# Sequence numbers automatically increment: 0, 1, 2
for enc in encrypted_msgs:
    print(f"Sequence: {enc['sequence']}")
```

### Replay Protection

```python
# Sender
encrypted = sender_crypto.encrypt(b"Message")

# Receiver validates sequence number
try:
    receiver_crypto.decrypt(
        encrypted['ciphertext'],
        encrypted['nonce'],
        sequence=0  # Expected sequence
    )
except ValueError as e:
    print(f"Replay attack detected: {e}")
```

## Performance

**Benchmark** (approximate, varies by hardware):

| Operation | Time | Throughput |
|-----------|------|------------|
| Encrypt 1 KB | ~5 ms | 200 KB/s |
| Decrypt 1 KB | ~5 ms | 200 KB/s |
| Encrypt 1 MB | ~5 s | 200 KB/s |

**Note**: This is significantly slower than AES-GCM (~1-2 GB/s). Phantom is designed for educational purposes, not high-performance applications.

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Detailed system design and cryptographic analysis
- **[API Documentation](#api-reference)**: Complete API reference
- **[Security Considerations](#security-considerations)**: Threat model and limitations

## API Reference

### PhantomCryptoSystem

Main interface for encryption/decryption.

```python
PhantomCryptoSystem(user_secret: bytes, salt: Optional[bytes] = None)
```

**Methods:**

- `encrypt(plaintext: bytes) -> dict`: Encrypt data
  - Returns: `{'ciphertext': bytes, 'nonce': bytes, 'sequence': int, 'salt': bytes}`
  
- `decrypt(ciphertext: bytes, nonce: bytes, sequence: Optional[int] = None) -> bytes`: Decrypt data
  - Raises `ValueError` on integrity failure or replay detection
  
- `get_salt() -> bytes`: Get the salt for key derivation
  
- `clear()`: Securely wipe sensitive data

### PhantomCipher

Low-level cipher interface for custom key management.

```python
PhantomCipher(
    permutation: Optional[PermutationLayer] = None,
    substitution: Optional[SubstitutionLayer] = None,
    state_mixer: Optional[StateMixer] = None,
    entropy_expander: Optional[EntropyExpander] = None
)
```

**Methods:**

- `encrypt(plaintext: bytes, key_schedule: MutatingKeySchedule, sequence_number: int) -> Tuple[bytes, bytes]`
- `decrypt(ciphertext: bytes, nonce: bytes, key_schedule: MutatingKeySchedule, expected_sequence: Optional[int]) -> bytes`

### MutatingKeySchedule

Key derivation with forward secrecy.

```python
MutatingKeySchedule(user_secret: bytes, salt: Optional[bytes] = None)
```

**Methods:**

- `derive_round_key(additional_entropy: Optional[bytes] = None) -> KeyState`
- `get_salt() -> bytes`
- `clear()`

## Security Considerations

### ✅ What Phantom Provides

1. **Strong Key Derivation**: BLAKE2b-based with 512-bit keys
2. **Multiple Security Layers**: Redundant protection
3. **Integrity Protection**: MAC prevents undetected tampering
4. **Forward Secrecy**: Old messages stay secure even if current state compromised
5. **Non-determinism**: Same plaintext produces different ciphertexts

### ⚠️ Limitations

1. **No Formal Security Proof**: Not mathematically proven secure
2. **Limited Cryptanalysis**: Not extensively analyzed by the community
3. **Timing Attacks**: S-box lookups may leak cache timing information
4. **Performance**: Much slower than standard algorithms
5. **Key Distribution**: Requires secure channel for key exchange (like all symmetric crypto)

### 🛡️ Threat Model

**Phantom defends against:**
- ✅ Ciphertext-only attacks
- ✅ Known-plaintext attacks (to a degree)
- ✅ Tampering and forgery attempts
- ✅ Replay attacks (when sequence validation used)
- ✅ Pattern analysis (due to non-determinism)

**Phantom does NOT defend against:**
- ❌ Side-channel attacks (timing, power, EM)
- ❌ Quantum computers (symmetric key exhaustion)
- ❌ Key compromise (if key is stolen, past messages with same nonce could be decrypted)
- ❌ Implementation bugs (always a risk in any software)

## Testing

The project includes comprehensive tests:

```bash
# Run all tests
python test_phantom_crypto.py

# Tests cover:
# - Individual component functionality
# - Encryption/decryption cycles
# - Security properties (tamper detection, replay resistance)
# - Edge cases (empty data, large data)
# - Avalanche effect and key sensitivity
```

All 38 tests pass ✅

## Use Cases

### ✅ Appropriate For

- Educational demonstrations of cryptographic concepts
- Research into custom cipher design
- Security training and Capture The Flag (CTF) challenges
- Prototyping novel cryptographic ideas
- Non-critical applications with unique requirements

### ❌ Not Appropriate For

- Production systems requiring proven security
- Financial or medical data
- Compliance requirements (FIPS, HIPAA, etc.)
- Critical infrastructure
- High-performance applications

## Contributing

Contributions are welcome! Areas of interest:

1. **Cryptanalysis**: Finding weaknesses or proving security properties
2. **Performance**: Optimizations without sacrificing security
3. **New Components**: Alternative layer implementations
4. **Testing**: Additional test cases and fuzzing
5. **Documentation**: Improvements and examples

## License

MIT License - See LICENSE file for details.

## Acknowledgments

Inspired by:
- Shannon's principles of confusion and diffusion
- Modern cipher designs (Rijndael, Serpent, ChaCha20)
- Forward secrecy concepts from Signal Protocol
- BLAKE2 cryptographic hash function

## Citation

If you use Phantom in academic work, please cite:

```
@software{phantom_crypto,
  title = {Phantom: A Research-Grade Encryption System},
  author = {v0idsh0id},
  year = {2024},
  url = {https://github.com/v0idsh0id/Phantom}
}
```

## Contact

For questions, issues, or research collaboration:
- GitHub Issues: https://github.com/v0idsh0id/Phantom/issues

---

**Remember**: For production use, stick with proven standards like AES-GCM or ChaCha20-Poly1305. Phantom is for learning and research! 🔬🔐
