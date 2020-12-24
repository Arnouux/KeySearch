package model;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
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

    public void openKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
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
            // tester si l'entrée nommée par l'alias courant est un certificat
            if(ks.isCertificateEntry(alias)) {
                certificates.add((X509Certificate) ks.getCertificate(alias));
            }
        }
        for (X509Certificate c : certificates) {
            System.out.println(c.getPublicKey());
        }
    }

    /*public void populate() throws NoSuchAlgorithmException {
        System.out.println("populate");

        // 1_Generate this.certs using CertificateBuilder and CertificateHandler
        // Certificate Issuer Distinguished Name
        final String DN = "CN=BestGroup, OU=2AIR, O=UHA, L=ScatteredInFrance, ST=24242, C=FR";
        X500Name caDn = new X500Name(DN);

        // CertificateBuilder
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKp = kpg.generateKeyPair();
        byte[] encodedPbKey = caKp.getPublic().getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(encodedPbKey);

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                // Issuer Name
                caDn,
                // Certificate ID
                generateId(),
                // Validity Period start
                new Date(System.currentTimeMillis()),
                // Validity Period end
                new Date(System.currentTimeMillis() + (long) 365 * 24 * 60 * 60 * 1000),
                // Subject Name
                caDn,
                // Public Key wrapped in Certificate
                subjectPublicKeyInfo
        );
        // CertificateHolder
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        PrivateKey caPk = caKp.getPrivate();
        AsymmetricKeyParameter privateKeyAsymKeyParam = null;
        try {
            privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caPk.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        }
        ContentSigner sigGen = null;
        try {
            sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
        X509CertificateHolder holder = builder.build(sigGen);

        try {
            InputStream is = new FileInputStream("key1.cer");
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(is);
            is.close();
            System.out.println(cert.toString());
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }

        // 2_Generate this.keys
        // 3_Generate this.ks
    }*/

    public void test(){
        /*
        X509Certificate c = certs.get(0);
        Principal p1 = c.getSubjectDN();
        Principal p2 = c.getIssuerDN();
        System.out.println("Subject: " + p1 + "\nIssuer: " + p2);
        */
        // 1.1_Try to find a certificate in this.certs by its DistinguishedName
        // 4_Try to find a certificate in this.ks by its DistinguishedName
        //
    }
}
