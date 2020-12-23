package model;

import java.security.*;
import java.util.List;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.*;
import java.math.BigInteger;

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

        // Le DN du CA
        final String DN = "CN=RootCA, OU=M2, O=miage, L=Mulhouse, ST=68093, C=FR";
        X500Name caDn = new X500Name(DN);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKp = kpg.generateKeyPair();
        byte[] encodedPbKey = caKp.getPublic().getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(encodedPbKey);

        // TODO: 1_Generate this.certs using CertificateBuilder and CertificateHandler
        this.certs = new X509v3CertificateBuilder(
                // nom de l'émetteur
                caDn,
                // numéro de série du certificat
                generateId(),
                // début de la période de validité
                new Date(System.currentTimeMillis()),
                // fin de la période de validité
                new Date(System.currentTimeMillis() + (long) 365 * 24 * 60 * 60 * 1000),
                // le nom du sujet
                caDn,
                // la clé publique enveloppée dans le certificat
                subjectPublicKeyInfo
        );


        X509v3CertificateBuilder v3CertGen;

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
