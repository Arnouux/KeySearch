package model;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.util.*;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import ui.App;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Model {
    private List<X509Certificate> certs;
    private List<PrivateKey> keys;
    private List<KeyStore> ks;

    private App app;

    public byte[] decrypt(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public byte[] encrypt(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public BigInteger generateId() {
        BigInteger counter = BigInteger.ONE;
        counter = counter.add(BigInteger.ONE);
        return counter;
    }

    public KeyType identifyKeyType(Key key){
        // TODO: Need to be re-done, to extract type from String
        KeyType result = KeyType.DSA;
        if(key instanceof ECPrivateKey || key instanceof ECPublicKey)
            result = KeyType.ECDSA;
        if(key instanceof RSAPrivateKey || key instanceof RSAPublicKey)
            result = KeyType.RSA;
        return result;
    }

    public void searchByKey(PrivateKey key, KeyStore ks) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        List<X509Certificate> certificates = new LinkedList<X509Certificate>();
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

    public void testGregoire() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        List<X509Certificate> certificates = new LinkedList<X509Certificate>();
        KeyStore ks = KeyStore.getInstance("JCEKS");
        InputStream is = new BufferedInputStream(new FileInputStream("store.ks"));
        ks.load(is, "abc123".toCharArray());
        Enumeration<String> aliases = ks.aliases();

        while(aliases.hasMoreElements()){
            String currAlias = aliases.nextElement();
            if(ks.isCertificateEntry(currAlias)) {
                certificates.add((X509Certificate) ks.getCertificate(currAlias));
            }
        }

        PrivateKey privKey = null;
        try{
            privKey = (PrivateKey) ks.getKey("firstKey", "abc123".toCharArray());
        } catch(ClassCastException e) {
            e.printStackTrace();
        }

        if(privKey instanceof DSAPrivateKey){
            System.out.println("DSA PrivateKey");
            searchInCertificates(certificates, "DSA", privKey);
        }
        else if(privKey instanceof ECPrivateKey){
            System.out.println("ECDSA PrivateKey");
            searchInCertificates(certificates, "ECDSA", privKey);
        }
        else if(privKey instanceof RSAPrivateKey){
            System.out.println("RSA PrivateKey");
            searchInCertificates(certificates, "RSA", privKey);
        }
        else if (privKey == null){
            System.out.println("Key not found");
        }
        else {
            System.out.println(privKey.getClass());
            System.out.println("Key type is not handled.");
        }
    }

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
                case "ECDSA":
                    System.out.println("ECDSA");
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

    public boolean validDSAKeyPair(DSAPrivateKey privKey, DSAPublicKey pubKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        // TODO: Verify if DSA public/private key pair is valid
        Signature signer = Signature.getInstance("SHA256withDSA");
        signer.initSign(privKey);
        byte[] message = "This message must be signed in DSA".getBytes(StandardCharsets.UTF_8);
        signer.update(message, 0, message.length);
        byte[] signatureGenerated = signer.sign();

        signer.initVerify(pubKey);
        signer.update(message, 0, message.length);
        return signer.verify(signatureGenerated);
    }

    public boolean validECDSAKeyPair(ECPrivateKey privKey, ECPublicKey pubKey){
        boolean result = false;
        // TODO: Verify if ECDSA public/private key pair is valid
        return result;
    }

    public boolean validRSAKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey){
        boolean result = false;

        String message =  "Hello decrypt me";

        byte[] encrypted = null;
        try {
            byte[] sut = message.getBytes(StandardCharsets.UTF_8);
            encrypted = encrypt(publicKey, sut);
            //System.out.println("ENCRYPTED : ");
            //System.out.println(new String(encrypted, "UTF-8"));
        } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        String decrypted = null;
        try {
            decrypted = new String(decrypt((PrivateKey) privateKey, encrypted), "UTF-8");
            //System.out.println("DECRYPTED : " + decrypted);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        //System.out.println(message.equals(decrypted));
        result = message.equals(decrypted);

        return result;
    }

    public void testArthur() {
        KeyStore ks = null;
        try {
            InputStream is = new BufferedInputStream(new FileInputStream("store.ks"));
            KeyStore ksTry = KeyStore.getInstance("JCEKS");
            ksTry.load(is, "abc123".toCharArray());
            ks = ksTry;
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            //e.printStackTrace();
        }
    }

    public void searchMatchCertificateAndKeys(TreeMap<String, PrivateKey> keys, X509Certificate certificate) {
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
        } else {
            System.out.println("No match found");
        }
    }
}
