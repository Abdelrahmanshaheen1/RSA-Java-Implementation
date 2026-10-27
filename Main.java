import java.io.IOException;
import java.util.Scanner;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter the desired key length (must be >= 256): ");
            int keyLength = scanner.nextInt();
            
            if (keyLength < 256) {
                System.err.println("Error: Key length must be 256 bits or greater");
                return;
            }
            
            //generating rsa key pair with entered length
            RSAKeyPair keyPair = new RSAKeyPair(keyLength);
            
            //paths of file
            String originalFile = "original.txt";
            String encryptedFile = "encrypted.txt";
            String decryptedFile = "decrypted.txt";
            
            //bet read el original methods
            String originalMessage = new String(Files.readAllBytes(Paths.get(originalFile)));
            
            //byprint el keys and message details
            System.out.println("\n=== Key and Message Details ===");
            System.out.println("Public Key (plaintext): " + keyPair.getPublicKey());
            System.out.println("Public Key (BigInteger):");
            System.out.println("  n: " + keyPair.getModulus());
            System.out.println("  e: " + keyPair.getPublicExponent());
            
            System.out.println("\nPrivate Key (plaintext): " + keyPair.getPrivateKey());
            System.out.println("Private Key (BigInteger):");
            System.out.println("  n: " + keyPair.getModulus());
            System.out.println("  d: " + keyPair.getPrivateExponent());
            
            System.out.println("\nOriginal Message (plaintext): " + originalMessage);
            System.out.println("Original Message (BigInteger):");
            byte[] messageBytes = originalMessage.getBytes();
            for (byte b : messageBytes) {
                System.out.print(BigInteger.valueOf(b & 0xFF) + " ");
            }
            System.out.println();
            
            //encrypting the file
            RSAEncryption.encryptFile(
                originalFile,
                encryptedFile,
                keyPair.getModulus(),
                keyPair.getPublicExponent()
            );
            
            //by2ra el encrypted message
            String encryptedMessage = new String(Files.readAllBytes(Paths.get(encryptedFile)));
            System.out.println("\nEncrypted Message (plaintext): " + encryptedMessage);
            System.out.println("Encrypted Message (BigInteger):");
            String[] encryptedNumbers = encryptedMessage.trim().split("\\s+");
            StringBuilder encryptedPlaintext = new StringBuilder();
            for (String num : encryptedNumbers) {
                if (!num.isEmpty()) {
                    BigInteger bigInt = new BigInteger(num);
                    System.out.print(bigInt + " ");
                    // Convert each byte of the BigInteger to ASCII
                    byte[] bytes = bigInt.toByteArray();
                    for (byte b : bytes) {
                        encryptedPlaintext.append((char) (b & 0xFF));
                    }
                }
            }
            System.out.println("\nEncrypted Message (ASCII): " + encryptedPlaintext.toString());
            
            //decrypting the file
            RSAEncryption.decryptFile(
                encryptedFile,
                decryptedFile,
                keyPair.getModulus(),
                keyPair.getPrivateExponent()
            );
            
            //by2ra el decrypted message
            String decryptedMessage = new String(Files.readAllBytes(Paths.get(decryptedFile)));
            System.out.println("\nDecrypted Message (plaintext): " + decryptedMessage);
            System.out.println("Decrypted Message (BigInteger):");
            byte[] decryptedBytes = decryptedMessage.getBytes();
            for (byte b : decryptedBytes) {
                System.out.print(BigInteger.valueOf(b & 0xFF) + " ");
            }
            System.out.println();
            
            System.out.println("\n=== File Operations Completed ===");
            System.out.println("Original file: " + originalFile);
            System.out.println("Encrypted file: " + encryptedFile);
            System.out.println("Decrypted file: " + decryptedFile);
            
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
} 