import model.*;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Main {
    private static Model model;

    public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
        model = new Model();
        //model.populate();
        model.openKeyStore();
        model.test();
    }
}
