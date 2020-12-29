import model.*;
import ui.App;

/**
 * Launcher
 */
public class Main {

    public static void main(String[] args) {
        Model model = new Model();

        App app = new App();
        app.pack();
        app.setVisible(true);
        app.setModel(model);
        model.setApp(app);
    }
}
