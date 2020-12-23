import model.Model;

import java.security.NoSuchAlgorithmException;

public class Main {
    private static Model model;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        model = new Model();
        model.populate();
        model.test();
    }
}
