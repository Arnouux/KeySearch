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
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Model {
    private List<X509Certificate> certs;
    private List<PrivateKey> keys;
    private List<KeyStore> ks;

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

    public void testArthur() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        List<X509Certificate> certificates = new LinkedList<X509Certificate>();
        KeyStore ks = KeyStore.getInstance("JCEKS");
        InputStream is = new BufferedInputStream(new FileInputStream("store.ks"));

        ks.load(is, "abc123".toCharArray());
        Enumeration<String> aliases = ks.aliases();

        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isCertificateEntry(alias)) {
                certificates.add((X509Certificate) ks.getCertificate(alias));
            }
        }
        /*
            // RECUPERATE PRIVATE KEYS SO WE CAN CHECK PUBLIC KEYS OF CERTS
            // ONLY VISIBLE ON KEY-ENTRYS
            //final Key key = (PrivateKey) ks.getKey(alias, "abc123".toCharArray());

            final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            final PublicKey publicKey = cert.getPublicKey();
            if (publicKey != null && key != null) {
                if(publicKey instanceof RSAPublicKey) {
                    System.out.println("RSA PublicKey :");
                    System.out.println(((RSAPublicKey) publicKey).getPublicExponent());
                    System.out.println("RSA public key hash : " + publicKey.hashCode());
                }
                if(publicKey instanceof DSAPublicKey) {
                    System.out.println("DSA PublicKey :");
                    System.out.println("P : " + ((DSAPublicKey) publicKey).getParams().getP());
                    System.out.println("G : " + ((DSAPublicKey) publicKey).getParams().getG());
                    System.out.println("Q : " + ((DSAPublicKey) publicKey).getParams().getQ());
                    System.out.println("DSA public key hash : " + publicKey.hashCode());
                }
            }

            if (key instanceof PrivateKey) {
                if(key instanceof RSAPrivateKey) {
                    System.out.println("RSA PrivateKey :");
                    System.out.println(((RSAPrivateKey) key).getPrivateExponent());
                    System.out.println("RSA private key hash : " + key.hashCode());
                }
                if(key instanceof DSAPrivateKey) {
                    System.out.println("DSA PrivateKey :");
                    System.out.println("P : " + ((DSAPrivateKey) key).getParams().getP());
                    System.out.println("G : " + ((DSAPrivateKey) key).getParams().getG());
                    System.out.println("Q : " + ((DSAPrivateKey) key).getParams().getQ());
                    System.out.println("DSA private key hash : " + key.hashCode());
                }
            }
        }*/

        PrivateKey key = null;
        try {
            key = (PrivateKey) ks.getKey("keyrsa", "abc123".toCharArray());
        } catch (ClassCastException e) {
            e.printStackTrace();
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
        else if (key == null) {
            System.out.println("Key not found");
        }
        else {
            System.out.println(key.getClass());
            System.out.println("Key type is not handled.");
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
            if (ks.isCertificateEntry(currAlias)) {
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
        for (X509Certificate c : certs) {
            switch (c.getPublicKey().getAlgorithm()) {
                case "DSA":
                    if (type.equals("DSA")) {
                        if(validDSAKeyPair((DSAPrivateKey) key, (DSAPublicKey) c.getPublicKey())) {
                            System.out.println(c.getIssuerDN());
                            tokenCertificateFound = true;
                        }
                    }
                    break;
                case "RSA":
                    if (type.equals("RSA")) {
                        if(validRSAKeyPair((RSAPrivateKey) key, (RSAPublicKey) c.getPublicKey())) {
                            System.out.println(c.getIssuerDN());
                            tokenCertificateFound = true;
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
        } else {
            System.out.println("No certificate found");
        }
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
}
