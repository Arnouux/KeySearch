package ui;

import javax.swing.*;
import java.awt.event.WindowEvent;

public class App extends JFrame {

    public App() {
        super("KeySearch");

        this.addWindowListener(new java.awt.event.WindowAdapter()
        {
            public void windowClosing(WindowEvent evt)
            {
                System.exit(0);
            }


        });

        JLabel label = new JLabel("Cryptography project, by Arthur, Bastien & Grégoire");
        this.add(label);
        this.pack();
    }
}

