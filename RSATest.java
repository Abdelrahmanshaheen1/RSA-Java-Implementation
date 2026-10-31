import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Self-contained tests, no test framework needed:
 *   javac *.java && java RSATest
 * Exits with a non-zero status if any check fails.
 */
public class RSATest {
    private static int passed = 0;

    private static void check(boolean condition, String name) {
        if (!condition) {
            System.err.println("FAIL: " + name);
            System.exit(1);
        }
        passed++;
        System.out.println("ok   " + name);
    }

    private static OAEPParameterSpec sha256Oaep() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    public static void main(String[] args) throws Exception {
        // ---- key generation ----
        for (int bits : new int[] {256, 257, 512, 1024}) {
            RSAKeyPair kp = new RSAKeyPair(bits);
            check(kp.getModulus().bitLength() == bits, "modulus has exactly " + bits + " bits");
            BigInteger probe = BigInteger.valueOf(123456789);
            BigInteger back = probe.modPow(kp.getPublicExponent(), kp.getModulus())
                                   .modPow(kp.getPrivateExponent(), kp.getModulus());
            check(back.equals(probe), bits + "-bit raw RSA round trip");
        }

        // ---- original per-byte scheme (educational) ----
        RSAKeyPair small = new RSAKeyPair(256);
        String text = "Hello RSA, éàü ✓ مرحبا";   // non-ASCII on purpose
        String enc = RSAEncryption.encrypt(text, small.getModulus(), small.getPublicExponent());
        check(RSAEncryption.decrypt(enc, small.getModulus(), small.getPrivateExponent()).equals(text),
              "per-byte scheme round-trips UTF-8 text");
        check(RSAEncryption.decrypt("", small.getModulus(), small.getPrivateExponent()).isEmpty(),
              "per-byte scheme handles an empty line");
        String twice = RSAEncryption.encrypt("aa", small.getModulus(), small.getPublicExponent());
        String[] parts = twice.split(" ");
        check(parts[0].equals(parts[1]), "per-byte scheme is deterministic: equal bytes give equal ciphertexts (why it is insecure)");

        // ---- OAEP ----
        RSAKeyPair kp = new RSAKeyPair(1024);
        BigInteger n = kp.getModulus(), e = kp.getPublicExponent(), d = kp.getPrivateExponent();
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.UTF_8);

        byte[] c1 = RSAOAEP.encrypt(msg, n, e);
        byte[] c2 = RSAOAEP.encrypt(msg, n, e);
        check(Arrays.equals(RSAOAEP.decrypt(c1, n, d), msg), "OAEP round trip");
        check(!Arrays.equals(c1, c2), "OAEP is randomised: same message gives different ciphertexts");
        check(Arrays.equals(RSAOAEP.decrypt(RSAOAEP.encrypt(new byte[0], n, e), n, d), new byte[0]), "OAEP empty message");

        byte[] longest = new byte[RSAOAEP.maxMessageLength(n)];
        Arrays.fill(longest, (byte) 0x7f);
        check(Arrays.equals(RSAOAEP.decrypt(RSAOAEP.encrypt(longest, n, e), n, d), longest), "OAEP maximum-length message");
        try {
            RSAOAEP.encrypt(new byte[longest.length + 1], n, e);
            check(false, "OAEP rejects an over-long message");
        } catch (IllegalArgumentException expected) {
            check(true, "OAEP rejects an over-long message");
        }

        byte[] tampered = c1.clone();
        tampered[tampered.length - 1] ^= 0x01;
        try {
            RSAOAEP.decrypt(tampered, n, d);
            check(false, "OAEP rejects a tampered ciphertext");
        } catch (GeneralSecurityException expected) {
            check(true, "OAEP rejects a tampered ciphertext");
        }

        // ---- interoperability with the JDK's implementation (SHA-256 / MGF1-SHA-256) ----
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey jdkPub = kf.generatePublic(new RSAPublicKeySpec(n, e));
        PrivateKey jdkPriv = kf.generatePrivate(new RSAPrivateKeySpec(n, d));

        Cipher jdk = Cipher.getInstance("RSA/ECB/OAEPPadding");
        jdk.init(Cipher.DECRYPT_MODE, jdkPriv, sha256Oaep());
        check(Arrays.equals(jdk.doFinal(RSAOAEP.encrypt(msg, n, e)), msg), "JDK decrypts what RSAOAEP encrypted");

        jdk.init(Cipher.ENCRYPT_MODE, jdkPub, sha256Oaep());
        byte[] fromJdk = jdk.doFinal(msg);
        check(Arrays.equals(RSAOAEP.decrypt(fromJdk, n, d), msg), "RSAOAEP decrypts what the JDK encrypted");

        System.out.println("\nAll " + passed + " checks passed.");
    }
}
