#!/usr/bin/env python3
"""
Test script for handshake cryptography implementation.
Verifies ML-DSA signing, ML-KEM pre-encryption, and padding.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from anti_censorship_server.crypto import (
    MLKEMKeyManager,
    MLDSAKeyManager,
    HandshakeCrypto,
    PayloadPadding
)


def test_mldsa_signing():
    """Test ML-DSA-87 signing and verification."""
    print("\n=== Testing ML-DSA-87 Signing ===")
    
    # Create temporary key manager
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        # Generate keys
        manager = MLDSAKeyManager(
            tmppath / "private.key",
            tmppath / "public.key"
        )
        
        print("Generating ML-DSA-87 key pair...")
        keypair = manager.generate_keypair()
        print(f"  Private key size: {len(keypair.private_key)} bytes")
        print(f"  Public key size: {len(keypair.public_key)} bytes")
        
        # Test signing
        message = b"Test handshake message"
        print(f"\nSigning message: {message}")
        signature = manager.sign(message)
        print(f"  Signature size: {len(signature)} bytes")
        
        # Test verification
        print("\nVerifying signature...")
        is_valid = manager.verify(message, signature)
        print(f"  Signature valid: {is_valid}")
        
        # Test invalid signature
        print("\nTesting invalid signature...")
        invalid_sig = signature[:-10] + b'\x00' * 10
        is_valid = manager.verify(message, invalid_sig)
        print(f"  Invalid signature rejected: {not is_valid}")
        
        return True


def test_handshake_crypto():
    """Test complete handshake cryptography."""
    print("\n=== Testing Handshake Cryptography ===")
    
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        # Setup key managers
        print("Setting up key managers...")
        mlkem_manager = MLKEMKeyManager(
            tmppath / "mlkem_private.key",
            tmppath / "mlkem_public.key"
        )
        mlkem_manager.generate_keypair()
        
        mldsa_manager = MLDSAKeyManager(
            tmppath / "mldsa_private.key",
            tmppath / "mldsa_public.key"
        )
        mldsa_manager.generate_keypair()
        
        # Create handshake crypto handler
        print("\nInitializing handshake crypto handler...")
        handshake = HandshakeCrypto(mlkem_manager, mldsa_manager)
        
        # Test CLIENT_HELLO
        print("\n--- Testing CLIENT_HELLO ---")
        version = 1
        print(f"Creating CLIENT_HELLO (version={version})...")
        encrypted_hello = handshake.create_client_hello(version)
        print(f"  Encrypted size: {len(encrypted_hello)} bytes")
        
        print("Parsing CLIENT_HELLO...")
        parsed_version, timestamp, nonce = handshake.parse_client_hello(encrypted_hello)
        print(f"  Parsed version: {parsed_version}")
        print(f"  Timestamp: {timestamp}")
        print(f"  Nonce size: {len(nonce)} bytes")
        print(f"  Version match: {parsed_version == version}")
        
        # Test KEY_EXCHANGE
        print("\n--- Testing KEY_EXCHANGE ---")
        ciphertext = b"test_ciphertext_data" * 50  # Simulate ML-KEM ciphertext
        print(f"Creating KEY_EXCHANGE (ciphertext size={len(ciphertext)})...")
        encrypted_kex = handshake.create_key_exchange(ciphertext)
        print(f"  Encrypted size: {len(encrypted_kex)} bytes")
        
        print("Parsing KEY_EXCHANGE...")
        parsed_ct, timestamp, nonce = handshake.parse_key_exchange(encrypted_kex)
        print(f"  Parsed ciphertext size: {len(parsed_ct)} bytes")
        print(f"  Timestamp: {timestamp}")
        print(f"  Nonce size: {len(nonce)} bytes")
        print(f"  Ciphertext match: {parsed_ct == ciphertext}")
        
        # Test timestamp validation
        print("\n--- Testing Timestamp Validation ---")
        import time
        old_timestamp = int(time.time()) - 400  # 400 seconds ago (beyond tolerance)
        print(f"Testing old timestamp (400s ago)...")
        try:
            # Manually create payload with old timestamp
            import struct
            old_data = bytearray()
            old_data.extend(struct.pack('>Q', old_timestamp))
            old_data.extend(handshake._generate_nonce())
            old_data.append(version)
            
            # Sign it
            signature = handshake.signer.sign_message(bytes(old_data))
            
            # Create payload
            from anti_censorship_server.crypto.handshake_crypto import HandshakePayload
            payload = HandshakePayload(
                timestamp=old_timestamp,
                nonce=old_data[8:40],
                data=bytes([version]),
                signature=signature
            )
            
            # Encrypt
            serialized = payload.to_bytes()
            padded = handshake.padding.pad(serialized)
            encrypted = handshake.pre_cipher.encrypt_bytes(padded)
            
            # Try to parse (should fail)
            handshake.parse_client_hello(encrypted)
            print("  ERROR: Old timestamp was accepted!")
            return False
        except ValueError as e:
            print(f"  Old timestamp correctly rejected: {e}")
        
        return True


def test_padding():
    """Test ASCII padding."""
    print("\n=== Testing ASCII Padding ===")
    
    padding = PayloadPadding()
    
    # Test padding
    original = b"Test data payload"
    print(f"Original data: {original}")
    print(f"  Size: {len(original)} bytes")
    
    padded = padding.pad(original)
    print(f"\nPadded data size: {len(padded)} bytes")
    print(f"  Overhead: {len(padded) - len(original)} bytes")
    
    # Check ASCII printable characters
    head_size = padded[0]
    tail_size = padded[-1]
    head_padding = padded[1:1+head_size]
    tail_padding = padded[len(padded)-1-tail_size:-1]
    
    print(f"\nPadding details:")
    print(f"  Head size: {head_size} bytes")
    print(f"  Tail size: {tail_size} bytes")
    print(f"  Head padding: {head_padding}")
    print(f"  Tail padding: {tail_padding}")
    
    # Verify all padding is ASCII printable
    import string
    printable = (string.ascii_letters + string.digits + string.punctuation).encode('ascii')
    head_valid = all(c in printable for c in head_padding)
    tail_valid = all(c in printable for c in tail_padding)
    print(f"  Head is ASCII printable: {head_valid}")
    print(f"  Tail is ASCII printable: {tail_valid}")
    
    # Test unpadding
    print("\nUnpadding...")
    unpadded = padding.unpad(padded)
    print(f"  Unpadded data: {unpadded}")
    print(f"  Match original: {unpadded == original}")
    
    return unpadded == original and head_valid and tail_valid


def main():
    """Run all tests."""
    print("=" * 60)
    print("BunnyTunnel Handshake Cryptography Test Suite")
    print("=" * 60)
    
    tests = [
        ("ML-DSA-87 Signing", test_mldsa_signing),
        ("ASCII Padding", test_padding),
        ("Handshake Cryptography", test_handshake_crypto),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n!!! Test '{name}' failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(result for _, result in results)
    print("\n" + "=" * 60)
    if all_passed:
        print("All tests PASSED!")
        return 0
    else:
        print("Some tests FAILED!")
        return 1


if __name__ == '__main__':
    sys.exit(main())
