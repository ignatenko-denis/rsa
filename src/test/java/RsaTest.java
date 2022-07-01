import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RsaTest {
    @Test
    public void string_rsa_encrypt_decrypt() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        String message = "Top secret message";
        Cipher encryptCipher = Cipher.getInstance("RSA");
        // encrypt message with public key
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = message.getBytes(UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

        Cipher decryptCipher = Cipher.getInstance("RSA");
        // decrypt message with private key
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, UTF_8);

        assertEquals(message, decryptedMessage);
    }

    @Test
    public void stream_rsa_encrypt_decrypt() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        Cipher encryptCipher = Cipher.getInstance("RSA");
        Cipher decryptCipher = Cipher.getInstance("RSA");

        // encrypt message with public key
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // decrypt message with private key
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        String message = "Top secret message";

        try (CipherInputStream encryptStream = new CipherInputStream(
                new ByteArrayInputStream(message.getBytes(UTF_8)), encryptCipher);
             ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream()) {

            // encryption
            IOUtils.copy(encryptStream, encryptedOutputStream);

            try (CipherInputStream decryptStream = new CipherInputStream(
                    new ByteArrayInputStream(encryptedOutputStream.toByteArray()), decryptCipher);
                 ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream()) {

                // decryption
                IOUtils.copy(decryptStream, decryptedOutputStream);

                String decryptedMessage = decryptedOutputStream.toString(UTF_8);
                assertEquals(message, decryptedMessage);
            }
        }
    }

    @Test
    public void file_stream_rsa_encrypt_decrypt() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        String message = "Top secret message";
        Path sourceFile = Files.createTempFile("temp_rsa_source_", ".txt");
        Files.writeString(sourceFile, message);
        Path encryptedFile = Files.createTempFile("temp_rsa_encrypted_", ".txt");
        Path decryptedFile = Files.createTempFile("temp_rsa_decrypted_", ".txt");

        Cipher encryptCipher = Cipher.getInstance("RSA");
        Cipher decryptCipher = Cipher.getInstance("RSA");

        // encrypt message with public key
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // decrypt message with private key
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        try (CipherInputStream encryptStream = new CipherInputStream(
                new FileInputStream(sourceFile.toFile()), encryptCipher);
             FileOutputStream encryptedOutputStream = new FileOutputStream(encryptedFile.toFile())) {
            // encryption
            IOUtils.copy(encryptStream, encryptedOutputStream);
        }

        try (CipherInputStream decryptStream = new CipherInputStream(
                new FileInputStream(encryptedFile.toFile()), decryptCipher);
             FileOutputStream decryptedOutputStream = new FileOutputStream(decryptedFile.toFile())) {
            // decryption
            IOUtils.copy(decryptStream, decryptedOutputStream);
        }

        try (Reader sourceReader = new BufferedReader(new FileReader(sourceFile.toFile()));
             Reader encryptedReader = new BufferedReader(new FileReader(decryptedFile.toFile()))) {

            assertTrue(IOUtils.contentEquals(sourceReader, encryptedReader));
        }
    }
}