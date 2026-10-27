import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class RSAKeyPair {
    private BigInteger n; // modulus
    private BigInteger e; // public exponent
    private BigInteger d; // private exponent
    private BigInteger p; // first prime
    private BigInteger q; // second prime
    private BigInteger phi; // Euler's totient function

    public RSAKeyPair() {
        this(256); //default = 256
    }

    public RSAKeyPair(int keyLength) {
        generateKeys(keyLength);
    }

    private void generateKeys(int keyLength) {
        //generate two large prime numbers
        Random random = new SecureRandom();
        int bitLength = keyLength / 2; //bysplit el key length between p and q
        
        p = BigInteger.probablePrime(bitLength, random);
        q = BigInteger.probablePrime(bitLength, random);
        
        //calculates n and phi
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        
        //chooses public exponent e
        e = BigInteger.valueOf(65537);
        
        //calculates private exponent d
        d = e.modInverse(phi);
    }

    public BigInteger getModulus() {
        return n;
    }

    public BigInteger getPublicExponent() {
        return e;
    }

    public BigInteger getPrivateExponent() {
        return d;
    }

    public String getPublicKey() {
        return n.toString() + "," + e.toString();
    }

    public String getPrivateKey() {
        return n.toString() + "," + d.toString();
    }
} 