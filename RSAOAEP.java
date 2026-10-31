import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * RSAES-OAEP (RFC 8017, section 7.1) with SHA-256 and MGF1-SHA-256, built on the
 * RSA primitive (modPow) from this repo. Only the hash function comes from the JDK.
 *
 * Unlike the byte-by-byte scheme in RSAEncryption, OAEP is randomised (encrypting the
 * same message twice gives different ciphertexts) and hides the message structure.
 * It is tested against the JDK's own "RSA/ECB/OAEPPadding" implementation in RSATest.
 *
 * The key must be at least 528 bits: a message block needs 2 * 32 + 2 bytes of overhead.
 */
public class RSAOAEP {
    private static final String HASH = "SHA-256";
    private static final int H_LEN = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Largest message (in bytes) that fits in one OAEP block for modulus n. */
    public static int maxMessageLength(BigInteger n) {
        return byteLength(n) - 2 * H_LEN - 2;
    }

    public static byte[] encrypt(byte[] message, BigInteger n, BigInteger e) {
        int k = byteLength(n);
        if (message.length > k - 2 * H_LEN - 2) {
            throw new IllegalArgumentException(
                "Message too long: at most " + (k - 2 * H_LEN - 2) + " bytes for this key size");
        }

        byte[] lHash = sha256(new byte[0]);

        // DB = lHash || PS (zeros) || 0x01 || M
        byte[] db = new byte[k - H_LEN - 1];
        System.arraycopy(lHash, 0, db, 0, H_LEN);
        db[db.length - message.length - 1] = 0x01;
        System.arraycopy(message, 0, db, db.length - message.length, message.length);

        byte[] seed = new byte[H_LEN];
        RANDOM.nextBytes(seed);

        byte[] maskedDb = xor(db, mgf1(seed, db.length));
        byte[] maskedSeed = xor(seed, mgf1(maskedDb, H_LEN));

        // EM = 0x00 || maskedSeed || maskedDB
        byte[] em = new byte[k];
        System.arraycopy(maskedSeed, 0, em, 1, H_LEN);
        System.arraycopy(maskedDb, 0, em, 1 + H_LEN, maskedDb.length);

        BigInteger c = new BigInteger(1, em).modPow(e, n);
        return toFixedLength(c, k);
    }

    public static byte[] decrypt(byte[] ciphertext, BigInteger n, BigInteger d) throws GeneralSecurityException {
        int k = byteLength(n);
        if (ciphertext.length != k || k < 2 * H_LEN + 2) {
            throw new GeneralSecurityException("Decryption error");
        }
        BigInteger c = new BigInteger(1, ciphertext);
        if (c.compareTo(n) >= 0) {
            throw new GeneralSecurityException("Decryption error");
        }

        byte[] em = toFixedLength(c.modPow(d, n), k);
        byte y = em[0];
        byte[] maskedSeed = Arrays.copyOfRange(em, 1, 1 + H_LEN);
        byte[] maskedDb = Arrays.copyOfRange(em, 1 + H_LEN, k);

        byte[] seed = xor(maskedSeed, mgf1(maskedDb, H_LEN));
        byte[] db = xor(maskedDb, mgf1(seed, maskedDb.length));

        // Check everything and fail with one generic error, so the caller cannot tell
        // which check failed (this is what makes padding-oracle attacks harder).
        boolean ok = (y == 0) && MessageDigest.isEqual(Arrays.copyOfRange(db, 0, H_LEN), sha256(new byte[0]));
        int separator = -1;
        for (int i = H_LEN; i < db.length; i++) {
            if (db[i] == 0x01) { separator = i; break; }
            if (db[i] != 0x00) { break; }
        }
        if (!ok || separator < 0) {
            throw new GeneralSecurityException("Decryption error");
        }
        return Arrays.copyOfRange(db, separator + 1, db.length);
    }

    // ---- helpers -------------------------------------------------------------

    /** MGF1 mask generation function (RFC 8017, appendix B.2.1). */
    static byte[] mgf1(byte[] seed, int length) {
        byte[] mask = new byte[length];
        int offset = 0;
        for (int counter = 0; offset < length; counter++) {
            byte[] input = Arrays.copyOf(seed, seed.length + 4);
            input[seed.length]     = (byte) (counter >>> 24);
            input[seed.length + 1] = (byte) (counter >>> 16);
            input[seed.length + 2] = (byte) (counter >>> 8);
            input[seed.length + 3] = (byte) counter;
            byte[] hash = sha256(input);
            int n = Math.min(hash.length, length - offset);
            System.arraycopy(hash, 0, mask, offset, n);
            offset += n;
        }
        return mask;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance(HASH).digest(data);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex); // every JDK ships SHA-256
        }
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    private static int byteLength(BigInteger n) {
        return (n.bitLength() + 7) / 8;
    }

    /** I2OSP: big-endian, exactly 'length' bytes (BigInteger.toByteArray may add or drop a leading zero). */
    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        if (raw.length > length) {                     // leading sign byte
            System.arraycopy(raw, raw.length - length, out, 0, length);
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }
}
