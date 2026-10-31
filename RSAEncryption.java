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
        //collect the decrypted bytes and decode them as UTF-8 at the end
        //(casting each byte to a char only works for plain ASCII)
        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        //bysplit el encrypted string to individual encrypted numbers
        for (String number : encrypted.trim().split("\\s+")) {
            if (number.isEmpty()) {
                continue; //empty line -> empty message
            }
            //converts string to BigInteger
            BigInteger c = new BigInteger(number);
            BigInteger m = c.modPow(d, n);
            decrypted.write(m.intValue());
        }

        return new String(decrypted.toByteArray(), StandardCharsets.UTF_8);
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