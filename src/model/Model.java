package model;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.util.*;

import ui.App;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Model {

    private App app;

    /**
     * Decrypts an encrypted statement using RSA cipher.
     * @param key the key to use to decrypt
     * @param ciphertext the text in bytes to decrypt
     * @return the decrypted array of bytes
     * @throws NoSuchAlgorithmException if "RSA/ECB/OAEPWithSHA1AndMGF1Padding" is not an usable algorithm
     * @throws InvalidKeyException if signer can't use the given key to sign or verify
     * @throws NoSuchPaddingException if padding is wrong
     * @throws BadPaddingException if padding is wrong
     * @throws IllegalBlockSizeException if block size is wrong
     */
    public byte[] decrypt(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Encrypts a statement using RSA cipher.
     * @param key the key to use to encrypt
     * @param plaintext the text to be encrypted
     * @return the encrypted array of bytes
     * @throws NoSuchAlgorithmException if "RSA/ECB/OAEPWithSHA1AndMGF1Padding" is not an usable algorithm
     * @throws InvalidKeyException if signer can't use the given key to sign or verify
     * @throws NoSuchPaddingException if padding is wrong
     * @throws BadPaddingException if padding is wrong
     * @throws IllegalBlockSizeException if block size is wrong
     */
    public byte[] encrypt(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Searches in the KeyStore given for a possible match for keys with the given private key.
     * @param key the private key we look a matching key for
     * @param ks the KeyStore from which we use Certificate entries.
     * @throws KeyStoreException if there is a problem in the KeyStore with aliases
     * @throws InvalidKeyException if signer can't use the given key to sign or verify
     * @throws NoSuchAlgorithmException if an usable algorithm is used
     * @throws SignatureException if signer can't sign the message
     */
    public void searchByKey(PrivateKey key, KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        List<X509Certificate> certificates = new LinkedList<>();
        Enumeration<String> aliases = ks.aliases();

        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isCertificateEntry(alias)) {
                certificates.add((X509Certificate) ks.getCertificate(alias));
            }
        }

        if(key instanceof RSAPrivateKey) {
            System.out.println("RSA PrivateKey");
            searchInCertificates(certificates, "RSA", key);
        }
        else if (key instanceof DSAPrivateKey) {
            System.out.println("DSA PrivateKey");
            searchInCertificates(certificates, "DSA", key);
        }
        else if (key instanceof ECPrivateKey) {
            System.out.println("ECDSA PrivateKey");
            searchInCertificates(certificates, "ECDSA", key);
        }
        else {
            System.out.println("Key type is not handled or false.");
        }
    }

    /**
     * Shows all the matching certificates (with the same DN) to the user.
     * @param dn the Distinguished Name we look for in the KeyStore
     * @param ks the KeyStore in which we search
     */
    public void searchByDN(String dn, KeyStore ks) {
        List<X509Certificate> certificates = new LinkedList<>();
        Enumeration<String> aliases = null;
        try {
            aliases = ks.aliases();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        while(true) {
            assert aliases != null;
            if (!aliases.hasMoreElements()) break;
            String alias = aliases.nextElement();
            try {
                if (ks.isCertificateEntry(alias)) {
                    certificates.add((X509Certificate) ks.getCertificate(alias));
                }
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        boolean tokenFound = false;
        List<X509Certificate> certificatesFound = new LinkedList<>();
        for (X509Certificate c : certificates) {
            System.out.println(c.getIssuerDN());
            if(c.getIssuerDN().toString().equals(dn)) {
                certificatesFound.add(c);
                tokenFound = true;
            }
        }
        if (tokenFound) {
            app.exportCertificates(certificatesFound);
        }
        else {
            System.out.println("No certificate found");
        }


    }

    /**
     * Searches in a list of certificates if a given private key matches one certificate's public key.
     * If a match is found, shows it to the user.
     * @param certs the list of certificates from the KeyStore we look in
     * @param type the type of algorithm used for the private key
     * @param key the private key we search a match for
     * @throws InvalidKeyException if signer can't use the given key to sign or verify
     * @throws NoSuchAlgorithmException if "SHA256withDSA" isn't an usable algorithm
     * @throws SignatureException if signer can't sign the message
     */
    private void searchInCertificates(List<X509Certificate> certs, String type, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        boolean tokenCertificateFound = false;
        X509Certificate matchCertificate = null;
        for (X509Certificate c : certs) {
            switch (c.getPublicKey().getAlgorithm()) {
                case "DSA":
                    if (type.equals("DSA")) {
                        if(validDSAKeyPair((DSAPrivateKey) key, (DSAPublicKey) c.getPublicKey())) {
                            System.out.println(c.getIssuerDN());
                            tokenCertificateFound = true;
                            matchCertificate = c;
                        }
                    }
                    break;
                case "RSA":
                    if (type.equals("RSA")) {
                        if(validRSAKeyPair((RSAPrivateKey) key, (RSAPublicKey) c.getPublicKey())) {
                            System.out.println(c.getIssuerDN());
                            tokenCertificateFound = true;
                            matchCertificate = c;
                        }
                    }
                    break;
                case "EC":
                    if (type.equals("ECDSA")) {
                        if(validECDSAKeyPair((ECPrivateKey) key, (ECPublicKey) c.getPublicKey())) {
                            System.out.println(c.getIssuerDN());
                            tokenCertificateFound = true;
                            matchCertificate = c;
                        }
                    }
                    break;
                default:
                    System.out.println("Algorithm unknown");
                    break;
            }
            if(tokenCertificateFound) {
                break;
            }
        }
        if(tokenCertificateFound) {
            System.out.println("Certificate found");
            app.exportCertificate(matchCertificate);
        } else {
            System.out.println("No certificate found");
        }
    }

    public void setApp(App app) {
        this.app = app;
    }

    /**
     * Checks if an DSA key pair matches.
     * Signs a test message using the private key and verify it using the public key.
     * @param privateKey the private key of the key pair
     * @param pubKey the public key of the key pair
     * @return true if keys match, false if not
     * @throws InvalidKeyException if signer can't use the given key to sign or verify
     * @throws NoSuchAlgorithmException if "SHA256withDSA" isn't an usable algorithm
     * @throws SignatureException if signer can't sign the message
     */
    public boolean validDSAKeyPair(DSAPrivateKey privateKey, DSAPublicKey pubKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withDSA");
        signer.initSign(privateKey);
        byte[] message = "This message must be signed in DSA".getBytes(StandardCharsets.UTF_8);
        signer.update(message, 0, message.length);
        byte[] signatureGenerated = signer.sign();

        signer.initVerify(pubKey);
        signer.update(message, 0, message.length);
        return signer.verify(signatureGenerated);
    }

    /**
     * Checks if an ECDSA key pair matches.
     * Signs a test message using the private key and verify it using the public key.
     * @param privateKey the private key of the key pair
     * @param pubKey the public key of the key pair
     * @return true if keys match, false if not
     * @throws InvalidKeyException if signer can't use the given key to sign or verify
     * @throws NoSuchAlgorithmException if "SHA256withDSA" isn't an usable algorithm
     * @throws SignatureException if signer can't sign the message
     */
    public boolean validECDSAKeyPair(ECPrivateKey privateKey, ECPublicKey pubKey) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        byte[] message = "This message must be signed in ECDSA".getBytes(StandardCharsets.UTF_8);
        signer.update(message, 0, message.length);
        byte[] signatureGenerated = signer.sign();

        signer.initVerify(pubKey);
        signer.update(message, 0, message.length);
        return signer.verify(signatureGenerated);
    }

    /**
     * Checks if a RSA key pair matches.
     * Encrypts a test String using public key and decrypt using private key.
     * @param privateKey the private key of the key pair
     * @param publicKey the public key of the key pair
     * @return true if keys match, false if not
     */
    public boolean validRSAKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey){
        String message =  "Hello decrypt me";

        byte[] encrypted = null;
        try {
            byte[] sut = message.getBytes(StandardCharsets.UTF_8);
            encrypted = encrypt(publicKey, sut);
        } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        String decrypted = null;
        try {
            decrypted = new String(decrypt(privateKey, encrypted), StandardCharsets.UTF_8);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return message.equals(decrypted);
    }

    /**
     * Given the public key's algorithm from the certificate, searches in the keys map if algorithm, and key pair match.
     * If a key pair is found, shows it.
     * @param keys a TreeMap of PrivateKey with the corresponding file name
     * @param certificate the certificate in which we look for a key
     * @throws InvalidKeyException if signer can't use the given key to sign or verify
     * @throws NoSuchAlgorithmException if "SHA256withDSA" isn't an usable algorithm
     * @throws SignatureException if signer can't sign the message
     */
    public void searchMatchCertificateAndKeys(TreeMap<String, PrivateKey> keys, X509Certificate certificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        boolean tokenKeyFound = false;
        PrivateKey matchKey = null;
        PublicKey publicKey = certificate.getPublicKey();
        String alg = publicKey.getAlgorithm();
        System.out.println(alg);
        switch (alg) {
            case "RSA":
                RSAPublicKey RSApublicKey = (RSAPublicKey) publicKey;
                for (Map.Entry<String,PrivateKey> key : keys.entrySet()) {
                    if(key.getValue().getAlgorithm().equals(alg)) {
                        if(validRSAKeyPair((RSAPrivateKey) key.getValue(), RSApublicKey)) {
                            System.out.println(key.getKey());
                            tokenKeyFound = true;
                            matchKey = key.getValue();
                            break;
                        }
                    }
                }
                break;
            case "DSA":
                DSAPublicKey DSApublicKey = (DSAPublicKey) publicKey;
                for (Map.Entry<String,PrivateKey> key : keys.entrySet()) {
                    if(key.getValue().getAlgorithm().equals(alg)) {
                        try {
                            if(validDSAKeyPair((DSAPrivateKey) key.getValue(), DSApublicKey)) {
                                System.out.println(key.getKey());
                                tokenKeyFound = true;
                                matchKey = key.getValue();
                                break;
                            }
                        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
                            e.printStackTrace();
                        }
                    }
                }
                break;
            case "ECDSA":
                ECPublicKey ECpublicKey = (ECPublicKey) publicKey;
                for (Map.Entry<String,PrivateKey> key : keys.entrySet()) {
                    if(key.getValue().getAlgorithm().equals(alg)) {
                        if(validECDSAKeyPair((ECPrivateKey) key.getValue(), ECpublicKey)) {
                            System.out.println(key.getKey());
                            tokenKeyFound = true;
                            matchKey = key.getValue();
                            break;
                        }
                    }
                }
                break;
            default:
                break;
        }

        if(tokenKeyFound) {
            System.out.println("Key found");
            System.out.println(matchKey);
        } else {
            System.out.println("No match found");
        }
    }
}
