import java.math.BigInteger;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class RSAEncryption {
    public static String encrypt(String message, BigInteger n, BigInteger e) {
        //creates empty string
        StringBuilder encrypted = new StringBuilder();
        //converting el input message le byte array ashan yb2a processed bel encryption algorithm
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        
        for (byte b : bytes) {
            //convert the byte to an unsigned BigInteger
            BigInteger m = BigInteger.valueOf(b & 0xFF);
            //c = m^e mod n
            BigInteger c = m.modPow(e, n);
            //append lel result separated by " "
            encrypted.append(c.toString()).append(" ");
        }
        //bysheel el " " el fel akher
        return encrypted.toString().trim();
    }

    public static String decrypt(String encrypted, BigInteger n, BigInteger d) {
        StringBuilder decrypted = new StringBuilder();
        //bysplit el encrypted string to individual encrypted numbers
        String[] numbers = encrypted.split(" ");
        
        for (String number : numbers) {
            //converts string to BigInteger
            BigInteger c = new BigInteger(number);
            BigInteger m = c.modPow(d, n);
            //byconvert el decrypted number le a character then appends to result
            decrypted.append((char) m.intValue());
        }
        
        return decrypted.toString();
    }

    public static void encryptFile(String inputFile, String outputFile, BigInteger n, BigInteger e) throws IOException {
        //byftah el input file ashan ye read and output file 3ashan ye write
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile));
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String encrypted = encrypt(line, n, e);
                //byktb el the encrypted line fel output file
                writer.write(encrypted);
                writer.newLine();
            }
        }
    }

    public static void decryptFile(String inputFile, String outputFile, BigInteger n, BigInteger d) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile));
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String decrypted = decrypt(line, n, d);
                writer.write(decrypted);
                writer.newLine();
            }
        }
    }
} 