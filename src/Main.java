import model.*;
import ui.App;

import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {
    private static Model model;

    public static void main(String[] args) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        model = new Model();
        //model.testArthur();
        //model.testGregoire();

        App app = new App();
        app.pack();
        app.setVisible(true);
        app.setModel(model);
        model.setApp(app);
    }
}
