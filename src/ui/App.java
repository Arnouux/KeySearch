package ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.WindowEvent;

public class App extends JFrame {

    // Key
    JTextArea textArea = new JTextArea(30, 10);
    JScrollPane jspKey = new JScrollPane(textArea);

    // Name
    JTextField input = new JTextField(20);
    JScrollPane jspName = new JScrollPane(input);

    public App() {
        super("KeySearch");

        this.addWindowListener(new java.awt.event.WindowAdapter()
        {
            public void windowClosing(WindowEvent evt)
            {
                System.exit(0);
            }


        });
        this.setPreferredSize(new Dimension(600, 600));

        this.setLayout(new BorderLayout());

        JLabel label = new JLabel("Cryptography project, by Arthur, Bastien & Grégoire");
        label.setHorizontalAlignment(JLabel.CENTER);
        this.add(label, BorderLayout.NORTH);


        JRadioButton optionKey = new JRadioButton("Private Key");
        optionKey.setVerticalAlignment(JLabel.NORTH);
        JRadioButton optionName = new JRadioButton("Distinguished Name");
        optionName.setHorizontalAlignment(JLabel.CENTER);
        optionName.setVerticalAlignment(JLabel.NORTH);
        JRadioButton optionCertificate = new JRadioButton("Certificate");
        optionCertificate.setVerticalAlignment(JLabel.NORTH);


        ButtonGroup group = new ButtonGroup();
        group.add(optionKey);
        group.add(optionName);
        group.add(optionCertificate);

        this.add(optionKey, BorderLayout.WEST);
        this.add(optionName, BorderLayout.CENTER);
        this.add(optionCertificate, BorderLayout.EAST);

        ItemListener listener = new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if(e.getStateChange() == 1) {
                    if (e.getSource() == optionKey) {
                        updatePanels("Key");
                    } else if (e.getSource() == optionName) {
                        updatePanels("Name");
                    } else if (e.getSource() == optionCertificate) {
                        updatePanels("Certificate");
                    }
                }
            }
        };

        optionKey.addItemListener(listener);
        optionName.addItemListener(listener);
        optionCertificate.addItemListener(listener);

        this.pack();
    }

    private void updatePanels(String value) {
        this.remove(jspKey);
        this.remove(jspName);

        switch(value) {
            case "Key":
                System.out.println("Key");
                this.add(jspKey, BorderLayout.SOUTH);
                this.setPreferredSize(new Dimension(600, 600));
                break;
            case "Name":
                System.out.println("Name");
                this.add(jspName, BorderLayout.SOUTH);
                this.setPreferredSize(new Dimension(600, 110));
                break;
            case "Certificate":
                System.out.println("Certificate");
                break;
            default:break;
        }
        this.pack();
    }
}

