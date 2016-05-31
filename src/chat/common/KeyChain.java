package chat.common;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Created by pedro on 5/28/16.
 *
 * Based on class KeyChain from
 * http://www.java-redefined.com/2014/03/symmetric-asymmetric-signature.html
 */
public class KeyChain {

    private KeyStore trustStore;
    private KeyStore keyStore;
    private String trustStorePass;
    private String keyStorePass;

    public KeyChain(String keyStoreFile, String keyStorePassword, String trustStoreFile, String trustStorePassword) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
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

    public byte[] signData(String alias, String msg) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, UnrecoverableKeyException, KeyStoreException {
        Signature dsa = Signature.getInstance("MD5withRSA");
        PrivateKey priv = (PrivateKey) keyStore.getKey(alias, keyStorePass.toCharArray());
        dsa.initSign(priv);
        dsa.update(msg.getBytes());
        return dsa.sign();
    }

    public boolean verifySignature(String alias, String msg, byte[] sigToVerify) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, KeyStoreException {
        Signature sig = Signature.getInstance("MD5withRSA");
        try {
            PublicKey pub = trustStore.getCertificate(alias).getPublicKey();
            sig.initVerify(pub);
            sig.update(msg.getBytes());
            return sig.verify(sigToVerify);
        } catch(NullPointerException e){
            System.out.println("Alias nonexistent");
            return false;
        }
    }

    public KeyStore getKeyStore(){
        return this.keyStore;
    }

    public String getKeyStorePass(){
        return this.keyStorePass;
    }

    public KeyStore getTrustStore(){
        return this.trustStore;
    }

    public String getTrustStorePass(){
        return this.trustStorePass;
    }

    /*DISCONTINUED METHODS
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
    */
}
