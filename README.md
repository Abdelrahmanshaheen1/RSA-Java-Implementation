# RSA Encryption — Java Implementation from Scratch

A from-scratch RSA implementation in Java using `BigInteger` — no external crypto libraries — covering key generation, encryption, and decryption at the byte level.

## What it does

- **`RSAKeyPair`** — generates a public/private key pair for a given key length: picks two probable primes (`BigInteger.probablePrime`), computes the modulus `n` and Euler's totient `φ(n)`, fixes the public exponent `e = 65537`, and derives the private exponent `d` as the modular inverse of `e` mod `φ(n)`.
- **`RSAEncryption`** — encrypts/decrypts byte-by-byte: each byte is treated as `m`, encrypted as `c = m^e mod n`, and decrypted as `m = c^d mod n`, with file-level helpers to encrypt/decrypt a whole text file line by line.
- **`Main`** — prompts for a key length (minimum 256 bits), generates a key pair, encrypts `original.txt` to `encrypted.txt`, decrypts it back to `decrypted.txt`, and prints the keys and message at each stage (plaintext, encrypted, and decrypted) alongside their raw `BigInteger` byte representations — useful for seeing exactly what RSA is doing under the hood rather than treating it as a black box.

## Verified

```bash
javac *.java
echo "256" | java Main
```
Compiles cleanly and round-trips correctly: encrypting then decrypting a test message reproduces the original byte-for-byte.

## Skills demonstrated

Public-key cryptography implemented from first principles — modular exponentiation, modular inverse, probable-prime generation — rather than just calling a library, which is the useful part for understanding *why* RSA is secure (and where it would break: no padding scheme is used here, so this is an educational implementation, not production-ready RSA).
