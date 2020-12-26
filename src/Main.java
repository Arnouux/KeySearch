import model.*;
import ui.App;

import javax.swing.*;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Main {
    private static Model model;

    public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, UnrecoverableKeyException {
        model = new Model();
        model.openKeyStore();

        App app = new App();
        app.pack();
        app.setVisible(true);
    }
}
