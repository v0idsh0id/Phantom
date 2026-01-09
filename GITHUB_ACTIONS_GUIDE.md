# Running Phantom on GitHub

This guide shows you how to run the Phantom cryptographic system directly on GitHub without installing anything locally.

## Automated Testing (Happens Automatically)

Every time you push code or create a pull request, GitHub Actions automatically:

1. ✅ Runs all 38 tests across Python 3.9, 3.10, 3.11, and 3.12
2. ✅ Executes the demo to verify functionality
3. ✅ Runs all examples to ensure they work
4. ✅ Validates code syntax

You can view results in the **Actions** tab of the repository.

## Manual Execution (On-Demand)

### Step-by-Step: Run Examples on GitHub

1. **Navigate to Actions Tab**
   - Go to the GitHub repository
   - Click on the **"Actions"** tab at the top

2. **Select Workflow**
   - On the left sidebar, click **"Run Examples"**

3. **Run Workflow**
   - Click the **"Run workflow"** dropdown button (right side)
   - Select branch: `copilot/design-unique-encryption-system` (or `main` after merge)
   - Choose what to run:
     - `all` - Run both demo and examples
     - `demo` - Run only the cryptographic system demo
     - `examples` - Run only the comprehensive examples
   - Click the green **"Run workflow"** button

4. **View Output**
   - Wait a few seconds for the workflow to start
   - Click on the workflow run that appears
   - Click on the job name (e.g., "run-demo" or "run-examples")
   - Expand the steps to see output
   - Look for sections like "Run Phantom Demo" or "Run Examples"

### What You'll See

**Demo Output:**
```
=== Phantom Cryptographic System Demo ===

Salt (hex): 3225c11f51bc7e778e276f130a460c0c...

Plaintext: Hello, this is a secret message that needs to be encrypted!
Plaintext size: 59 bytes

Ciphertext size: 204 bytes
Ciphertext (hex): 00000001000000000000000095a67593a9d3...
Nonce (hex): c877de1607d6b1e7b7094a57c0011877...
Sequence: 0

Decrypted: Hello, this is a secret message that needs to be encrypted!
Match: True

Testing replay resistance...
✓ Replay attack detected: Sequence number mismatch: expected 999, got 0

Testing tamper detection...
✓ Tampering detected: MAC verification failed - data may be tampered

=== Demo Complete ===
```

**Examples Output:**
```
╔==========================================================╗
║          PHANTOM CRYPTOGRAPHIC SYSTEM                    ║
║                  Usage Examples                          ║
╚==========================================================╝

============================================================
Example 1: Basic Encryption/Decryption
============================================================
Original message: This is a secret message!
Encrypted (first 32 bytes): 000000010000000000000000bca62ea4...
✓ Success! Messages match: True

... (and 4 more examples)
```

## Viewing Test Results

1. Go to the **Actions** tab
2. Click on any workflow run (e.g., "CI" or "Tests")
3. View the test summary and detailed logs
4. See which tests passed/failed and error messages if any

## CI/CD Badges

The README shows the current status:

[![CI](https://github.com/v0idsh0id/Phantom/workflows/CI/badge.svg)](https://github.com/v0idsh0id/Phantom/actions/workflows/ci.yml)
[![Tests](https://github.com/v0idsh0id/Phantom/workflows/Tests/badge.svg)](https://github.com/v0idsh0id/Phantom/actions/workflows/test.yml)

- ✅ Green badge = All tests passing
- ❌ Red badge = Some tests failing

## Available Workflows

### 1. CI (Continuous Integration)
- **Trigger**: Automatic on push/PR
- **What it does**: Full testing across Python versions
- **File**: `.github/workflows/ci.yml`

### 2. Tests
- **Trigger**: Automatic on push/PR
- **What it does**: Quick test validation
- **File**: `.github/workflows/test.yml`

### 3. Run Examples
- **Trigger**: Manual only (workflow_dispatch)
- **What it does**: Run demo and/or examples on demand
- **File**: `.github/workflows/run-examples.yml`

## Benefits of Running on GitHub

1. **No Installation Required** - Just click and run
2. **Multiple Python Versions** - See compatibility across 3.9-3.12
3. **Clean Environment** - Fresh Python environment every time
4. **Shareable Results** - Send links to workflow runs
5. **Continuous Verification** - Automatically catches breaking changes

## Troubleshooting

**Q: I don't see the "Run workflow" button**
- Make sure you're on the Actions tab
- Select the "Run Examples" workflow from the left sidebar
- The button appears on the right side above the workflow runs

**Q: The workflow is "queued" for a long time**
- GitHub Actions can have queue times
- Free tier has usage limits
- Usually starts within 1-2 minutes

**Q: Can I run this on my fork?**
- Yes! The workflows will automatically work on any fork
- Just push the code and GitHub Actions will be available

## Next Steps

After running on GitHub, you might want to:
- Clone the repo locally and run: `python test_phantom_crypto.py`
- Try modifying examples and pushing to see CI results
- Read `ARCHITECTURE.md` for deep cryptographic analysis
- Check `REQUIREMENTS_VERIFICATION.md` for compliance details

---

**No local installation needed - run everything on GitHub!** 🚀
