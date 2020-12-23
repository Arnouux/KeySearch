package model;

import java.util.List;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.*;

public class Model {

    private List<X509Certificate> certs;
    private List<PrivateKey> keys;
    private List<KeyStore> ks;

    public void populate(){
        // TODO: 1_Generate this.certs using CertificateBuilder and CertificateHandler
        System.out.println("populate");
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
