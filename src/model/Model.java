package model;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
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

    public KeyType identifyPrivateKeyType(Key key){
        KeyType result = KeyType.DSA;
        if(key instanceof ECPrivateKey || key instanceof ECPublicKey)
            result = KeyType.ECDSA;
        if(key instanceof RSAPrivateKey || key instanceof RSAPublicKey)
            result = KeyType.RSA;
        return result;
    }

    public void openKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        List<X509Certificate> certificates = new LinkedList<X509Certificate>();
        KeyStore ks = KeyStore.getInstance("JCEKS");
        InputStream is = new BufferedInputStream(new FileInputStream("store.ks"));

        // Test
        byte[] encrypted = null;

        ks.load(is, "abc123".toCharArray());
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if(ks.isCertificateEntry(alias)) {
                certificates.add((X509Certificate) ks.getCertificate(alias));
            }

            // RECUPERATE PRIVATE KEYS SO WE CAN CHECK PUBLIC KEYS OF CERTS
            // ONLY VISIBLE ON KEY-ENTRYS
            final Key key = (PrivateKey) ks.getKey(alias, "abc123".toCharArray());

            final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            final PublicKey publicKey = cert.getPublicKey();
            if (publicKey != null && key != null) {
                if(publicKey instanceof RSAPublicKey) {
                    /*System.out.println("RSA PublicKey :");
                    System.out.println(((RSAPublicKey) publicKey).getPublicExponent());*/
                    System.out.println("RSA public key hash : " + publicKey.hashCode());

                    try {
                        byte[] sut = "Hello decrypt me".getBytes(StandardCharsets.UTF_8);
                        encrypted = encrypt(publicKey, sut);
                        System.out.println("ENCRYPTED : ");
                        System.out.println(new String(encrypted, "UTF-8"));
                    } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }
                }
                if(publicKey instanceof DSAPublicKey) {
                    /*System.out.println("DSA PublicKey :");
                    System.out.println("P : " + ((DSAPublicKey) publicKey).getParams().getP());
                    System.out.println("G : " + ((DSAPublicKey) publicKey).getParams().getG());
                    System.out.println("Q : " + ((DSAPublicKey) publicKey).getParams().getQ());*/
                    System.out.println("DSA public key hash : " + publicKey.hashCode());
                }
            }

            if (key instanceof PrivateKey) {
                if(key instanceof RSAPrivateKey) {
                    /*System.out.println("RSA PrivateKey :");
                    System.out.println(((RSAPrivateKey) key).getPrivateExponent());*/

                    System.out.println("RSA private key hash : " + key.hashCode());

                    try {
                        byte[] decrypted = decrypt((PrivateKey) key, encrypted);
                        System.out.println("DECRYPTED : " + new String(decrypted, "UTF-8"));
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    }
                }
                if(key instanceof DSAPrivateKey) {
                    /*System.out.println("DSA PrivateKey :");
                    System.out.println("P : " + ((DSAPrivateKey) key).getParams().getP());
                    System.out.println("G : " + ((DSAPrivateKey) key).getParams().getG());
                    System.out.println("Q : " + ((DSAPrivateKey) key).getParams().getQ());*/

                    System.out.println("DSA private key hash : " + key.hashCode());
                }
            }
        }
        for (X509Certificate c : certificates) {
            System.out.println(c.getSubjectX500Principal());
            switch(c.getPublicKey().getAlgorithm()) {
                case "DSA" :
                    System.out.println("DSA");
                    System.out.println(c.getPublicKey().hashCode());
                    break;
                case "RSA" :
                    System.out.println("RSA");
                    System.out.println(c.getPublicKey().hashCode());
                    break;
                case "ECDSA" :
                    System.out.println("ECDSA");
                    break;
                default:
                    System.out.println("Algorithm unknown");
                    break;
            }
        }
    }

    public boolean validDSAKeyPair(DSAPublicKey pubKey, DSAPrivateKey privKey){
        boolean result = false;
        // TODO: Verify if DSA public/private key pair is valid
        // Get p, g, y parameters from pubKey
        // Check if y = g^privKey mod p
        // Yes => result = true;
        return result;
    }

    public boolean validECDSAKeyPair(ECPublicKey pubKey, ECPrivateKey privKey){
        boolean result = false;
        // TODO: Verify if ECDSA public/private key pair is valid
        return result;
    }

    public boolean validRSAKeyPair(RSAPublicKey pubKey, RSAPrivateKey privKey){
        boolean result = false;
        // TODO: Verify if RSA public/private key pair is valid
        return result;
    }
}
