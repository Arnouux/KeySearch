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

    private void test(){
        X509Certificate c = certs.get(0);
        Principal p1 = c.getSubjectDN();
        Principal p2 = c.getIssuerDN();
        System.out.println("Subject: " + p1 + "\nIssuer: " + p2);
    }

    public void populate(){
        X509v3CertificateBuilder v3CertGen;
    }
}
