#!/usr/bin/env python3
"""
BlackRoad OS Hashing Utilities
SHA-256 and SHA-Infinity implementations for Python

Compatible with: Python 3.8+, Pyto (iOS), iSH, standard Linux/macOS

@module utils/hash
@version 2.0.0
@license BlackRoad OS Proprietary
"""

import hashlib
import secrets
import json
import time
import base64
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict


@dataclass
class HashResult:
    """Result of a hash operation"""
    hash: str
    algorithm: str
    base_algorithm: str
    iterations: int
    salt: str
    timestamp: str
    compute_time_ms: float
    verification_string: str
    previous_hash: Optional[str] = None


class SHA256:
    """SHA-256 Hash Implementation"""

    @staticmethod
    def hash(message: str) -> str:
        """
        Hash a string using SHA-256

        Args:
            message: The message to hash

        Returns:
            Hex-encoded hash
        """
        return hashlib.sha256(message.encode('utf-8')).hexdigest()

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        """
        Hash bytes using SHA-256

        Args:
            data: The bytes to hash

        Returns:
            Hex-encoded hash
        """
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_file(filepath: str) -> str:
        """
        Hash a file using SHA-256

        Args:
            filepath: Path to the file

        Returns:
            Hex-encoded hash
        """
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def verify(message: str, expected_hash: str) -> bool:
        """
        Verify a hash matches expected value

        Args:
            message: The message to verify
            expected_hash: The expected hash

        Returns:
            True if hashes match
        """
        actual_hash = SHA256.hash(message)
        return actual_hash == expected_hash.lower()


class SHAInfinity:
    """
    SHA-Infinity: Recursive/Iterative Hashing for Enhanced Security

    Applies SHA-256 recursively with configurable depth and salt injection.
    The "infinity" concept: hash can be extended infinitely by increasing
    iterations, with each iteration building on the previous hash + metadata.
    """

    DEFAULT_ITERATIONS = 1000
    MAX_ITERATIONS = 1_000_000
    SALT_LENGTH = 32

    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """
        Generate cryptographically secure random salt

        Args:
            length: Salt length in bytes

        Returns:
            Hex-encoded salt
        """
        return secrets.token_hex(length)

    @staticmethod
    def hash(
        message: str,
        iterations: Optional[int] = None,
        salt: Optional[str] = None,
        include_metadata: bool = True
    ) -> HashResult:
        """
        SHA-Infinity Hash - Recursive hashing with salt injection

        Args:
            message: The message to hash
            iterations: Number of hash iterations (default: 1000)
            salt: Salt value (auto-generated if not provided)
            include_metadata: Include iteration count in hash

        Returns:
            HashResult with hash and metadata
        """
        iterations = min(
            iterations or SHAInfinity.DEFAULT_ITERATIONS,
            SHAInfinity.MAX_ITERATIONS
        )
        salt = salt or SHAInfinity.generate_salt(SHAInfinity.SALT_LENGTH)

        start_time = time.time()

        # Initial hash with salt
        current_hash = SHA256.hash(salt + message)

        # Iterative hashing
        for i in range(1, iterations):
            iteration_salt = f"{i}:" if include_metadata else ""
            current_hash = SHA256.hash(iteration_salt + current_hash)

        end_time = time.time()
        compute_time_ms = (end_time - start_time) * 1000

        return HashResult(
            hash=current_hash,
            algorithm='sha-infinity',
            base_algorithm='SHA-256',
            iterations=iterations,
            salt=salt,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            compute_time_ms=round(compute_time_ms, 2),
            verification_string=f"$sha-inf${iterations}${salt}${current_hash}"
        )

    @staticmethod
    def parse_verification_string(verification_string: str) -> Optional[Dict[str, Any]]:
        """
        Parse a verification string

        Args:
            verification_string: The verification string

        Returns:
            Parsed components or None if invalid
        """
        parts = [p for p in verification_string.split('$') if p]
        if len(parts) != 4 or parts[0] != 'sha-inf':
            return None

        return {
            'algorithm': 'sha-infinity',
            'iterations': int(parts[1]),
            'salt': parts[2],
            'hash': parts[3]
        }

    @staticmethod
    def verify(
        message: str,
        verification_string: Union[str, Dict[str, Any], HashResult]
    ) -> bool:
        """
        Verify a message against a SHA-Infinity hash

        Args:
            message: The message to verify
            verification_string: The verification string, dict, or HashResult

        Returns:
            True if verification succeeds
        """
        if isinstance(verification_string, str):
            params = SHAInfinity.parse_verification_string(verification_string)
            if not params:
                return False
        elif isinstance(verification_string, HashResult):
            params = {
                'iterations': verification_string.iterations,
                'salt': verification_string.salt,
                'hash': verification_string.hash
            }
        elif isinstance(verification_string, dict):
            params = verification_string
        else:
            return False

        result = SHAInfinity.hash(
            message,
            iterations=params['iterations'],
            salt=params['salt'],
            include_metadata=True
        )

        return result.hash == params['hash']

    @staticmethod
    def extend(existing_result: HashResult, additional_iterations: int = 1000) -> HashResult:
        """
        Extend an existing hash with additional iterations

        Args:
            existing_result: Previous hash result
            additional_iterations: More iterations to apply

        Returns:
            Extended hash result
        """
        current_hash = existing_result.hash
        start_iteration = existing_result.iterations
        total_iterations = start_iteration + additional_iterations

        start_time = time.time()

        for i in range(start_iteration, total_iterations):
            current_hash = SHA256.hash(f"{i}:{current_hash}")

        end_time = time.time()
        compute_time_ms = (end_time - start_time) * 1000

        return HashResult(
            hash=current_hash,
            algorithm='sha-infinity',
            base_algorithm=existing_result.base_algorithm,
            iterations=total_iterations,
            salt=existing_result.salt,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            compute_time_ms=round(compute_time_ms, 2),
            verification_string=f"$sha-inf${total_iterations}${existing_result.salt}${current_hash}",
            previous_hash=existing_result.hash
        )

    @staticmethod
    def chain(inputs: List[str], iterations: int = 100, salt: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a hash chain (merkle-like) from multiple inputs

        Args:
            inputs: Array of inputs to chain
            iterations: Iterations per hash
            salt: Optional salt

        Returns:
            Chain result with all intermediate hashes
        """
        chain_hashes = []
        previous_hash = ''
        salt = salt or SHAInfinity.generate_salt()

        for inp in inputs:
            combined = previous_hash + inp
            result = SHAInfinity.hash(combined, iterations=iterations, salt=salt)
            chain_hashes.append({
                'input': inp[:20] + ('...' if len(inp) > 20 else ''),
                'hash': result.hash
            })
            previous_hash = result.hash

        return {
            'final_hash': previous_hash,
            'chain_length': len(inputs),
            'chain': chain_hashes,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }


class HashUtils:
    """Utility functions for hashing common data types"""

    @staticmethod
    def hash_object(obj: Any) -> str:
        """
        Hash a Python object (JSON serializable)

        Args:
            obj: Object to hash

        Returns:
            SHA-256 hash
        """
        json_str = json.dumps(obj, sort_keys=True, separators=(',', ':'))
        return SHA256.hash(json_str)

    @staticmethod
    def hash_object_secure(obj: Any, **options) -> HashResult:
        """
        Hash a Python object with SHA-Infinity

        Args:
            obj: Object to hash
            **options: Hashing options

        Returns:
            SHA-Infinity result
        """
        json_str = json.dumps(obj, sort_keys=True, separators=(',', ':'))
        return SHAInfinity.hash(json_str, **options)

    @staticmethod
    def create_content_id(data: Any) -> str:
        """
        Create a content-addressable ID from data

        Args:
            data: Data to create ID from

        Returns:
            Content ID (first 16 chars of hash)
        """
        if isinstance(data, str):
            data_str = data
        else:
            data_str = json.dumps(data, sort_keys=True)

        full_hash = SHA256.hash(data_str)
        return full_hash[:16]

    @staticmethod
    def keyed_hash(key: str, message: str) -> str:
        """
        HMAC-like keyed hash

        Args:
            key: Secret key
            message: Message to authenticate

        Returns:
            Keyed hash
        """
        import hmac
        return hmac.new(
            key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def generate_token(payload: Dict[str, Any], secret: str, expires_in: int = 3600) -> Dict[str, Any]:
        """
        Generate a hash-based token

        Args:
            payload: Token payload
            secret: Secret key
            expires_in: Expiration in seconds

        Returns:
            Token object
        """
        expires = int(time.time() * 1000) + (expires_in * 1000)
        data = {**payload, 'exp': expires}
        data_str = json.dumps(data, sort_keys=True)
        signature = HashUtils.keyed_hash(secret, data_str)

        token_obj = {'data': data, 'signature': signature}
        encoded = base64.b64encode(json.dumps(token_obj).encode()).decode()

        return {
            'data': data,
            'signature': signature,
            'encoded': encoded
        }

    @staticmethod
    def verify_token(encoded: str, secret: str) -> Optional[Dict[str, Any]]:
        """
        Verify a hash-based token

        Args:
            encoded: Encoded token
            secret: Secret key

        Returns:
            Decoded payload or None if invalid
        """
        try:
            decoded = json.loads(base64.b64decode(encoded))
            data = decoded['data']
            signature = decoded['signature']

            # Check expiration
            if 'exp' in data and int(time.time() * 1000) > data['exp']:
                return None

            # Verify signature
            data_str = json.dumps(data, sort_keys=True)
            expected_sig = HashUtils.keyed_hash(secret, data_str)
            if signature != expected_sig:
                return None

            return data
        except Exception:
            return None


# CLI interface for direct usage
if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='BlackRoad OS Hashing Utilities')
    parser.add_argument('command', choices=['sha256', 'sha-inf', 'verify', 'file'])
    parser.add_argument('input', help='Input string or file path')
    parser.add_argument('-i', '--iterations', type=int, default=1000, help='Iterations for SHA-Infinity')
    parser.add_argument('-s', '--salt', help='Salt for SHA-Infinity')
    parser.add_argument('-v', '--verify', help='Hash to verify against')

    args = parser.parse_args()

    if args.command == 'sha256':
        print(SHA256.hash(args.input))

    elif args.command == 'sha-inf':
        result = SHAInfinity.hash(args.input, iterations=args.iterations, salt=args.salt)
        print(json.dumps(asdict(result), indent=2))

    elif args.command == 'verify':
        if not args.verify:
            print("Error: --verify required for verify command")
            sys.exit(1)
        is_valid = SHAInfinity.verify(args.input, args.verify)
        print(f"Valid: {is_valid}")
        sys.exit(0 if is_valid else 1)

    elif args.command == 'file':
        print(SHA256.hash_file(args.input))
