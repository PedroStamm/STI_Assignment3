package chat.common;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Created by pedro on 5/28/16.
 */
public class KeyStoreUtil {

    private KeyStore trustStore;
    private KeyStore keyStore;
    private String trustStorePass;
    private String keyStorePass;

    private Cipher dCipher;
    private Cipher eCipher;

    public KeyStoreUtil(String keyStoreFile, String keyStorePassword, String trustStoreFile, String trustStorePassword) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        loadKeyStore(keyStoreFile, keyStorePassword);
        loadTrustStore(trustStoreFile, trustStorePassword);
    }

    private void loadKeyStore(String filepath, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        this.keyStore = KeyStore.getInstance("JCEKS");
        this.keyStorePass = password;
        FileInputStream stream = new FileInputStream(filepath);
        this.keyStore.load(stream, this.keyStorePass.toCharArray());
    }

    private void loadTrustStore(String filepath, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        this.trustStore = KeyStore.getInstance("JCEKS");
        this.trustStorePass = password;
        FileInputStream stream = new FileInputStream(filepath);
        this.trustStore.load(stream, this.trustStorePass.toCharArray());
    }

    public byte[] generateSessionKey(int size) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(size);
        SecretKey key = generator.generateKey();
        return(key.getEncoded());
    }

    public String encryptWithAES(String data, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey secKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] newData = cipher.doFinal(data.getBytes());
        return Base64.encode(newData);
    }

    public String decryptWithAES(String data, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, Base64DecodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secKey = new SecretKeySpec(Base64.decode(key.getBytes()), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] newData = cipher.doFinal(Base64.decode(data.getBytes()));
        return new String(newData);
    }

}
