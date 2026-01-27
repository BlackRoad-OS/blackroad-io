/**
 * BlackRoad OS Hashing Utilities
 * SHA-256 and SHA-Infinity implementations
 *
 * @module utils/hash
 * @version 2.0.0
 * @license BlackRoad OS Proprietary
 */

/**
 * SHA-256 Hash Implementation
 * Uses Web Crypto API for browser compatibility
 */
class SHA256 {
  /**
   * Hash a string using SHA-256
   * @param {string} message - The message to hash
   * @returns {Promise<string>} - Hex-encoded hash
   */
  static async hash(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Hash a file/blob using SHA-256
   * @param {Blob|File} blob - The blob to hash
   * @returns {Promise<string>} - Hex-encoded hash
   */
  static async hashBlob(blob) {
    const buffer = await blob.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Verify a hash matches expected value
   * @param {string} message - The message to verify
   * @param {string} expectedHash - The expected hash
   * @returns {Promise<boolean>} - True if hashes match
   */
  static async verify(message, expectedHash) {
    const actualHash = await this.hash(message);
    return actualHash === expectedHash.toLowerCase();
  }
}

/**
 * SHA-Infinity: Recursive/Iterative Hashing for Enhanced Security
 * Applies SHA-256 recursively with configurable depth and salt injection
 *
 * The "infinity" concept: hash can be extended infinitely by increasing iterations,
 * with each iteration building on the previous hash + metadata
 */
class SHAInfinity {
  /**
   * Default configuration
   */
  static DEFAULT_CONFIG = {
    baseAlgorithm: 'SHA-256',
    defaultIterations: 1000,
    maxIterations: 1000000,
    saltLength: 32,
    includeMetadata: true
  };

  /**
   * Generate cryptographically secure random salt
   * @param {number} length - Salt length in bytes
   * @returns {string} - Hex-encoded salt
   */
  static generateSalt(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * SHA-Infinity Hash - Recursive hashing with salt injection
   * @param {string} message - The message to hash
   * @param {Object} options - Hashing options
   * @param {number} options.iterations - Number of hash iterations (default: 1000)
   * @param {string} options.salt - Salt value (auto-generated if not provided)
   * @param {boolean} options.includeMetadata - Include iteration count in hash
   * @returns {Promise<Object>} - Hash result with metadata
   */
  static async hash(message, options = {}) {
    const config = { ...this.DEFAULT_CONFIG, ...options };
    const iterations = Math.min(config.iterations || config.defaultIterations, config.maxIterations);
    const salt = config.salt || this.generateSalt(config.saltLength);

    let currentHash = message;
    const startTime = Date.now();

    // Initial hash with salt
    currentHash = await SHA256.hash(salt + currentHash);

    // Iterative hashing
    for (let i = 1; i < iterations; i++) {
      // Inject iteration number into hash chain for uniqueness
      const iterationSalt = config.includeMetadata ? `${i}:` : '';
      currentHash = await SHA256.hash(iterationSalt + currentHash);
    }

    const endTime = Date.now();

    return {
      hash: currentHash,
      algorithm: 'sha-infinity',
      baseAlgorithm: config.baseAlgorithm,
      iterations: iterations,
      salt: salt,
      timestamp: new Date().toISOString(),
      computeTimeMs: endTime - startTime,
      // Verification string format: $sha-inf$iterations$salt$hash
      verificationString: `$sha-inf$${iterations}$${salt}$${currentHash}`
    };
  }

  /**
   * Parse a verification string
   * @param {string} verificationString - The verification string
   * @returns {Object|null} - Parsed components or null if invalid
   */
  static parseVerificationString(verificationString) {
    const parts = verificationString.split('$').filter(Boolean);
    if (parts.length !== 4 || parts[0] !== 'sha-inf') {
      return null;
    }
    return {
      algorithm: 'sha-infinity',
      iterations: parseInt(parts[1], 10),
      salt: parts[2],
      hash: parts[3]
    };
  }

  /**
   * Verify a message against a SHA-Infinity hash
   * @param {string} message - The message to verify
   * @param {string} verificationString - The verification string (or hash object)
   * @returns {Promise<boolean>} - True if verification succeeds
   */
  static async verify(message, verificationString) {
    let params;

    if (typeof verificationString === 'string') {
      params = this.parseVerificationString(verificationString);
      if (!params) return false;
    } else if (typeof verificationString === 'object') {
      params = verificationString;
    } else {
      return false;
    }

    const result = await this.hash(message, {
      iterations: params.iterations,
      salt: params.salt,
      includeMetadata: true
    });

    return result.hash === params.hash;
  }

  /**
   * Extend an existing hash with additional iterations
   * Useful for "infinite" hash extension
   * @param {Object} existingResult - Previous hash result
   * @param {number} additionalIterations - More iterations to apply
   * @returns {Promise<Object>} - Extended hash result
   */
  static async extend(existingResult, additionalIterations = 1000) {
    let currentHash = existingResult.hash;
    const startIteration = existingResult.iterations;
    const totalIterations = startIteration + additionalIterations;
    const startTime = Date.now();

    for (let i = startIteration; i < totalIterations; i++) {
      currentHash = await SHA256.hash(`${i}:${currentHash}`);
    }

    const endTime = Date.now();

    return {
      hash: currentHash,
      algorithm: 'sha-infinity',
      baseAlgorithm: existingResult.baseAlgorithm,
      iterations: totalIterations,
      salt: existingResult.salt,
      timestamp: new Date().toISOString(),
      computeTimeMs: endTime - startTime,
      previousHash: existingResult.hash,
      verificationString: `$sha-inf$${totalIterations}$${existingResult.salt}$${currentHash}`
    };
  }

  /**
   * Create a hash chain (merkle-like) from multiple inputs
   * @param {string[]} inputs - Array of inputs to chain
   * @param {Object} options - Hashing options
   * @returns {Promise<Object>} - Chain result with all intermediate hashes
   */
  static async chain(inputs, options = {}) {
    const chainHashes = [];
    let previousHash = '';

    for (const input of inputs) {
      const combined = previousHash + input;
      const result = await this.hash(combined, {
        iterations: options.iterations || 100,
        salt: options.salt || this.generateSalt()
      });
      chainHashes.push({
        input: input.substring(0, 20) + (input.length > 20 ? '...' : ''),
        hash: result.hash
      });
      previousHash = result.hash;
    }

    return {
      finalHash: previousHash,
      chainLength: inputs.length,
      chain: chainHashes,
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Utility functions for hashing common data types
 */
class HashUtils {
  /**
   * Hash a JavaScript object (JSON)
   * @param {Object} obj - Object to hash
   * @returns {Promise<string>} - SHA-256 hash
   */
  static async hashObject(obj) {
    const json = JSON.stringify(obj, Object.keys(obj).sort());
    return SHA256.hash(json);
  }

  /**
   * Hash a JavaScript object with SHA-Infinity
   * @param {Object} obj - Object to hash
   * @param {Object} options - Hashing options
   * @returns {Promise<Object>} - SHA-Infinity result
   */
  static async hashObjectSecure(obj, options = {}) {
    const json = JSON.stringify(obj, Object.keys(obj).sort());
    return SHAInfinity.hash(json, options);
  }

  /**
   * Create a content-addressable ID from data
   * @param {any} data - Data to create ID from
   * @returns {Promise<string>} - Content ID (first 16 chars of hash)
   */
  static async createContentId(data) {
    const str = typeof data === 'string' ? data : JSON.stringify(data);
    const hash = await SHA256.hash(str);
    return hash.substring(0, 16);
  }

  /**
   * HMAC-like keyed hash
   * @param {string} key - Secret key
   * @param {string} message - Message to authenticate
   * @returns {Promise<string>} - Keyed hash
   */
  static async keyedHash(key, message) {
    // Simple HMAC-like construction: H(key || H(key || message))
    const innerHash = await SHA256.hash(key + message);
    return SHA256.hash(key + innerHash);
  }

  /**
   * Generate a hash-based token
   * @param {Object} payload - Token payload
   * @param {string} secret - Secret key
   * @param {number} expiresIn - Expiration in seconds
   * @returns {Promise<Object>} - Token object
   */
  static async generateToken(payload, secret, expiresIn = 3600) {
    const expires = Date.now() + (expiresIn * 1000);
    const data = { ...payload, exp: expires };
    const dataStr = JSON.stringify(data);
    const signature = await this.keyedHash(secret, dataStr);

    return {
      data: data,
      signature: signature,
      encoded: Buffer.from(JSON.stringify({ data, signature })).toString('base64')
    };
  }

  /**
   * Verify a hash-based token
   * @param {string} encoded - Encoded token
   * @param {string} secret - Secret key
   * @returns {Promise<Object|null>} - Decoded payload or null if invalid
   */
  static async verifyToken(encoded, secret) {
    try {
      const decoded = JSON.parse(Buffer.from(encoded, 'base64').toString());
      const { data, signature } = decoded;

      // Check expiration
      if (data.exp && Date.now() > data.exp) {
        return null;
      }

      // Verify signature
      const expectedSig = await this.keyedHash(secret, JSON.stringify(data));
      if (signature !== expectedSig) {
        return null;
      }

      return data;
    } catch {
      return null;
    }
  }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SHA256, SHAInfinity, HashUtils };
}

if (typeof window !== 'undefined') {
  window.BlackRoadHash = { SHA256, SHAInfinity, HashUtils };
}

// ES Module export
export { SHA256, SHAInfinity, HashUtils };
