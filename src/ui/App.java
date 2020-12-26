package ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class App extends JFrame {

    // Key
    JTextArea textArea = new JTextArea(30, 10);
    JScrollPane jspKey = new JScrollPane(textArea);

    // Name
    JTextField input = new JTextField(20);
    JScrollPane jspName = new JScrollPane(input);

    // Certificate
    JFileChooser fileChooserCertificate = new JFileChooser(System.getProperty("user.dir"));
    JFileChooser fileChooserKeys = new JFileChooser(System.getProperty("user.dir"));
    JButton buttonOpenFileChooserCertificate = new JButton("Certificate");
    JButton buttonOpenFileChooserKeys = new JButton("Keys file");
    JLabel fileCertificateName = new JLabel("");
    JLabel fileKeysName = new JLabel("");
    JPanel btnPanel = new JPanel(new GridLayout(2,2, 10, 2));

    JPanel centerPanel = new JPanel();
    JPanel endPanel = new JPanel();

    public App() {
        super("KeySearch");

        this.addWindowListener(new java.awt.event.WindowAdapter()
        {
            public void windowClosing(WindowEvent evt)
            {
                System.exit(0);
            }


        });

        buttonOpenFileChooserCertificate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showFileChooser("Certificate");
            }
        });
        buttonOpenFileChooserKeys.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showFileChooser("Keys");
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

        this.centerPanel.setLayout(new BorderLayout());
        this.centerPanel.add(optionKey, BorderLayout.WEST);
        this.centerPanel.add(optionName, BorderLayout.CENTER);
        this.centerPanel.add(optionCertificate, BorderLayout.EAST);

        //this.add(optionKey, BorderLayout.WEST);
        //this.add(optionName, BorderLayout.CENTER);
        //this.add(optionCertificate, BorderLayout.EAST);

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

        //centerPanel.setPreferredSize(new Dimension(500, 500));
        this.add(centerPanel, BorderLayout.CENTER);

        this.endPanel.setLayout(new BorderLayout());
        JLabel endLabel = new JLabel("--------------------------------------------------------------------------------------------------------------------------------------------------");
        this.endPanel.add(endLabel, BorderLayout.NORTH);
        JButton searchButton = new JButton("Search !");
        this.endPanel.add(searchButton, BorderLayout.SOUTH);
        this.add(endPanel, BorderLayout.SOUTH);
        this.pack();
    }

    private void updatePanels(String value) {
        this.centerPanel.remove(jspKey);
        this.centerPanel.remove(jspName);
        this.centerPanel.remove(buttonOpenFileChooserKeys);
        this.centerPanel.remove(buttonOpenFileChooserCertificate);
        this.centerPanel.remove(btnPanel);

        switch(value) {
            case "Key":
                System.out.println("Key");
                this.centerPanel.add(jspKey, BorderLayout.SOUTH);
                this.setPreferredSize(new Dimension(600, 600));
                break;
            case "Name":
                System.out.println("Name");
                this.centerPanel.add(jspName, BorderLayout.SOUTH);
                this.setPreferredSize(new Dimension(600, 150));
                break;
            case "Certificate":
                System.out.println("Certificate");

                btnPanel.add(buttonOpenFileChooserCertificate);
                btnPanel.add(fileCertificateName);
                btnPanel.add(buttonOpenFileChooserKeys);
                btnPanel.add(fileKeysName);

                this.centerPanel.add(btnPanel, BorderLayout.SOUTH);
                //fileChooserCertificate.showOpenDialog(this);
                this.setPreferredSize(new Dimension(600, 190));
                break;
            default:break;
        }
        this.pack();
        this.repaint();
    }

    private void showFileChooser(String value) {
        switch(value) {
            case "Certificate":
                fileChooserCertificate.showOpenDialog(this);
                this.fileCertificateName.setText(fileChooserCertificate.getSelectedFile().getName());
                break;
            case "Keys":
                fileChooserKeys.showOpenDialog(this);
                this.fileKeysName.setText(fileChooserKeys.getSelectedFile().getName());
                break;
            default:break;
        }
    }

}

