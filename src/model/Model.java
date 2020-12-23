package model;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;
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

public class Model {

    private List<X509Certificate> certs;
    private List<PrivateKey> keys;
    private List<KeyStore> ks;

    public BigInteger generateId() {
        BigInteger counter = BigInteger.ONE;
        counter = counter.add(BigInteger.ONE);
        return counter;
    }

    public void populate() throws NoSuchAlgorithmException {
        System.out.println("populate");

        // Certificate Issuer Distinguished Name
        final String DN = "CN=RootCA, OU=M2, O=BestGroup, L=SomewhereInFrance, ST=24242, C=FR";
        X500Name caDn = new X500Name(DN);

        // TODO: 1_Generate this.certs using CertificateBuilder and CertificateHandler
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

        // TODO: 2_Generate this.keys
        // TODO: 3_Generate this.ks
    }

    public void test(){
        /*
        X509Certificate c = certs.get(0);
        Principal p1 = c.getSubjectDN();
        Principal p2 = c.getIssuerDN();
        System.out.println("Subject: " + p1 + "\nIssuer: " + p2);
        */
        // TODO: 1.1_Try to find a certificate in this.certs by its DistinguishedName
        // TODO: 4_Try to find a certificate in this.ks by its DistinguishedName
        //
    }
}
