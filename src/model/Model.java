package model;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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

public class Model {
    private List<X509Certificate> certs;
    private List<PrivateKey> keys;
    private List<KeyStore> ks;

    public BigInteger generateId() {
        BigInteger counter = BigInteger.ONE;
        counter = counter.add(BigInteger.ONE);
        return counter;
    }

    public KeyType identifyKeyType(){
        KeyType result;
        // TODO: Identify KeyType from Key
        result = KeyType.RSA;
        return result;
    }

    public void openKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        List<X509Certificate> certificates = new LinkedList<X509Certificate>();
        KeyStore ks = KeyStore.getInstance("JCEKS");
        InputStream is = new BufferedInputStream(new FileInputStream("store.ks"));
        char[] pwd = new char[6];
        for (int i= 0; i<6; i++) {
            pwd[i] = "abc123".charAt(i);
        }
        ks.load(is, pwd);
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if(ks.isCertificateEntry(alias)) {
                certificates.add((X509Certificate) ks.getCertificate(alias));
            }

            // RECUPERATE PRIVATE KEYS SO WE CAN CHECK PUBLIC KEYS OF CERTS
            // ONLY VISIBLE ON KEY-ENTRYS
            /*final Key key = (PrivateKey) ks.getKey(alias, "abc123".toCharArray());

            final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            final PublicKey publicKey = cert.getPublicKey();
            System.out.println("publicKey : \n" + publicKey);
            System.out.println("privateKey : \n" + key);*/
        }
        for (X509Certificate c : certificates) {
            System.out.println(c.getSubjectX500Principal());
            switch(c.getPublicKey().getAlgorithm()) {
                case "DSA" :
                    System.out.println("DSA");
                    break;
                case "RSA" :
                    System.out.println("RSA");
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

    public boolean ValidDSAKeyPair(DSAPublicKey pubKey, DSAPrivateKey privKey){
        boolean result;
        // TODO: Verify if DSA public/private key pair is valid
        result = false;
        return result;
    }

    public boolean ValidECDSAKeyPair(){
        // TODO: WTF is an ECDSA key??!
        return false;
    }

    public boolean ValidRSAKeyPair(RSAPublicKey pubKey, RSAPrivateKey privKey){
        boolean result;
        // TODO: Verify if RSA public/private key pair is valid
        result = false;
        return result;
    }

}
