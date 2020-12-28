package ui;
import model.KeyType;
import model.Model;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.List;

public class App extends JFrame {
    private Model model;
    private KeyStore ks;
    private PrivateKey privateKey;
    public void setModel(Model model) {
        this.model = model;
    }
    JButton searchButton;


    JFileChooser fileChooserKeyStore = new JFileChooser(System.getProperty("user.dir"));
    JLabel fileKeyStore = new JLabel("");
    // Key
    JTextArea textArea = new JTextArea(30, 10);
    JScrollPane jspKey = new JScrollPane(textArea);
    JButton buttonOpenKeyStore = new JButton("KeyStore");
    JPanel panelKey = new JPanel(new BorderLayout());

    // Name
    JTextField input = new JTextField(20);
    JScrollPane jspName = new JScrollPane(input);
    JPanel panelName = new JPanel(new BorderLayout());

    // Certificate
    List<File> listFileChooserKeys = new LinkedList<>();
    JFileChooser fileChooserCertificate = new JFileChooser(System.getProperty("user.dir"));
    JFileChooser fileChooserKeys = new JFileChooser(System.getProperty("user.dir"));
    JButton buttonOpenFileChooserCertificate = new JButton("Certificate");
    JButton buttonOpenFileChooserKeys = new JButton("Key file");
    JLabel fileCertificateName = new JLabel("");
    JLabel fileKeysName = new JLabel("0 file selected");
    JPanel btnPanel = new JPanel(new GridLayout(3,2, 10, 2));
    JButton buttonResetFileKeys = new JButton("Reset");

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

        buttonOpenKeyStore.addActionListener(e -> showFileChooser("KeyStore"));
        buttonOpenFileChooserCertificate.addActionListener(e -> showFileChooser("Certificate"));
        buttonOpenFileChooserKeys.addActionListener(e -> showFileChooser("Keys"));
        buttonResetFileKeys.addActionListener(e -> resetListKeyFiles());

        this.setPreferredSize(new Dimension(600, 600));

        this.setLayout(new BorderLayout());

        JLabel label = new JLabel("Cryptography project, by Arthur, Bastien & Grégoire - ENSISA 2020");
        label.setHorizontalAlignment(JLabel.CENTER);
        this.add(label, BorderLayout.NORTH);


        JRadioButton optionKey = new JRadioButton("Private Key");
        optionKey.setVerticalAlignment(JLabel.NORTH);
        JRadioButton optionName = new JRadioButton("Distinguished Name");
        optionName.setHorizontalAlignment(JLabel.CENTER);
        optionName.setVerticalAlignment(JLabel.NORTH);
        JRadioButton optionCertificate = new JRadioButton("Certificate & keys");
        optionCertificate.setVerticalAlignment(JLabel.NORTH);


        ButtonGroup group = new ButtonGroup();
        group.add(optionKey);
        group.add(optionName);
        group.add(optionCertificate);

        this.centerPanel.setLayout(new BorderLayout());
        this.centerPanel.add(optionKey, BorderLayout.WEST);
        this.centerPanel.add(optionName, BorderLayout.CENTER);
        this.centerPanel.add(optionCertificate, BorderLayout.EAST);

        ItemListener listener = e -> {
            if(e.getStateChange() == ItemEvent.SELECTED) {
                if (e.getSource() == optionKey) {
                    updatePanels("Key");
                } else if (e.getSource() == optionName) {
                    updatePanels("Name");
                } else if (e.getSource() == optionCertificate) {
                    updatePanels("Certificate");
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

        searchButton = new JButton("Search !");
        searchButton.setEnabled(false);
        ActionListener searchListener = e -> {
            for (Enumeration<AbstractButton> buttons = group.getElements(); buttons.hasMoreElements();) {
                AbstractButton button = buttons.nextElement();

                if (button.isSelected()) {
                    if(button == optionKey) {
                        String text = textArea.getText();
                        privateKey = base64toPrivateKey(text);

                        try {
                            model.searchByKey(privateKey, ks);
                        } catch (KeyStoreException | NoSuchAlgorithmException | SignatureException | InvalidKeyException error) {
                            error.printStackTrace();
                        }
                    }
                    else if (button == optionName) {
                        System.out.println(input.getText());
                        model.searchByDN(input.getText(), ks);
                    }
                    else if (button == optionCertificate) {
                        System.out.println(fileCertificateName.getText());
                        CertificateFactory fact;
                        FileInputStream is;
                        X509Certificate certificate = null;
                        try {
                            fact = CertificateFactory.getInstance("X.509");
                            is = new FileInputStream(fileChooserCertificate.getSelectedFile());
                            certificate = (X509Certificate) fact.generateCertificate(is);
                        } catch (CertificateException | FileNotFoundException certificateException) {
                            certificateException.printStackTrace();
                        }
                        TreeMap<String, PrivateKey> keys = new TreeMap<>();
                        for(File f : listFileChooserKeys) {
                            try {
                                FileInputStream fis = new FileInputStream(f);
                                byte[] data = new byte[(int) f.length()];
                                int r = fis.read(data);
                                if(r > 0) {
                                    PrivateKey key = base64toPrivateKey(new String(data, StandardCharsets.UTF_8));
                                    keys.put(f.getName(), key);
                                }
                                fis.close();
                            } catch (IOException error) {
                                error.printStackTrace();
                            }

                        }
                        assert certificate != null;
                        try {
                            model.searchMatchCertificateAndKeys(keys, certificate);
                        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException error) {
                            error.printStackTrace();
                        }
                    }
                }
            }
        };
        searchButton.addActionListener(searchListener);
        this.endPanel.add(searchButton, BorderLayout.SOUTH);
        this.add(endPanel, BorderLayout.SOUTH);
        this.pack();
    }

    /**
     * Decodes a base64 text to the corresponding key.
     * @param text the base64 encoded text to decode
     * @return the private key from the decoded base64
     */
    private PrivateKey base64toPrivateKey(String text) {
        text = text.replace("-----BEGIN PRIVATE KEY-----", "");
        text = text.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        text = text.replace("-----BEGIN DSA PRIVATE KEY-----", "");
        text = text.replace("-----BEGIN EC PRIVATE KEY-----", "");
        text = text.replace("-----END PRIVATE KEY-----", "");
        text = text.replace("-----END RSA PRIVATE KEY-----", "");
        text = text.replace("-----END DSA PRIVATE KEY-----", "");
        text = text.replace("-----END EC PRIVATE KEY-----", "");
        text = text.replaceAll("\\s+","");
        byte[] decodedBytes = java.util.Base64.getDecoder().decode(text);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedBytes);
        KeyFactory kf;
        PrivateKey privateKey = null;

        for(KeyType type : KeyType.values()) {
            try {
                kf = KeyFactory.getInstance(type.name());
                privateKey = kf.generatePrivate(keySpec);
                break;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException error) {
                System.out.println("Not " + type.name() + " key type.");
            }
        }
        return privateKey;
    }

    /**
     * Resets the list of files of keys if the Reset button is pressed
     */
    private void resetListKeyFiles() {
        this.fileKeysName.setText("0 file selected");
        this.listFileChooserKeys = new LinkedList<>();
        searchButton.setEnabled(false);
    }

    /**
     * Shows to the user the panel corresponding to the option chosen.
     * @param value the value of the selected radio button
     */
    private void updatePanels(String value) {
        this.centerPanel.remove(jspKey);
        this.centerPanel.remove(jspName);
        this.centerPanel.remove(buttonOpenFileChooserKeys);
        this.centerPanel.remove(buttonOpenFileChooserCertificate);
        this.centerPanel.remove(btnPanel);
        this.centerPanel.remove(panelKey);
        this.centerPanel.remove(panelName);

        switch(value) {
            case "Key":
                panelKey.add(buttonOpenKeyStore, BorderLayout.WEST);
                panelKey.add(fileKeyStore, BorderLayout.CENTER);
                panelKey.add(jspKey, BorderLayout.SOUTH);
                searchButton.setEnabled(fileChooserKeyStore.getSelectedFile() != null);
                this.centerPanel.add(panelKey, BorderLayout.SOUTH);
                this.setPreferredSize(new Dimension(600, 650));
                break;
            case "Name":
                panelName.add(buttonOpenKeyStore, BorderLayout.WEST);
                panelName.add(fileKeyStore, BorderLayout.CENTER);
                panelName.add(jspName, BorderLayout.SOUTH);
                searchButton.setEnabled(fileChooserKeyStore.getSelectedFile() != null);
                this.centerPanel.add(panelName, BorderLayout.SOUTH);
                this.setPreferredSize(new Dimension(600, 190));
                break;
            case "Certificate":
                btnPanel.add(buttonOpenFileChooserCertificate);
                btnPanel.add(fileCertificateName);
                btnPanel.add(buttonOpenFileChooserKeys);
                btnPanel.add(fileKeysName);
                btnPanel.add(buttonResetFileKeys);
                searchButton.setEnabled(fileChooserCertificate.getSelectedFile() != null && fileChooserKeys.getSelectedFile() != null);
                this.centerPanel.add(btnPanel, BorderLayout.SOUTH);
                //fileChooserCertificate.showOpenDialog(this);
                this.setPreferredSize(new Dimension(600, 210));
                break;
            default:break;
        }
        this.pack();
        this.repaint();
    }

    /**
     * Shows the file chooser window to the user.
     * Saves the file and informs the user of it.
     * @param value the value of the selected radio button
     */
    private void showFileChooser(String value) {
        switch(value) {
            case "Certificate":
                fileChooserCertificate.showOpenDialog(this);
                if (fileChooserCertificate.getSelectedFile() != null) {
                    this.fileCertificateName.setText(fileChooserCertificate.getSelectedFile().getName());
                }
                break;
            case "Keys":
                fileChooserKeys.showOpenDialog(this);
                if (fileChooserKeys.getSelectedFile() != null) {
                    this.listFileChooserKeys.add(fileChooserKeys.getSelectedFile());
                    if (this.listFileChooserKeys.size() == 1) {
                        this.fileKeysName.setText(this.listFileChooserKeys.size() + " key file selected");
                    }
                    else if (this.listFileChooserKeys.size() > 1) {
                        this.fileKeysName.setText(this.listFileChooserKeys.size() + " key files selected");
                    }
                }
                break;
            case "KeyStore":
                fileChooserKeyStore.showOpenDialog(this);
                if (fileChooserKeyStore.getSelectedFile() != null) {
                    String pwd = JOptionPane.showInputDialog("Password : ");
                    InputStream is = null;
                    try {
                        is = new BufferedInputStream(new FileInputStream(fileChooserKeyStore.getSelectedFile()));
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                    KeyStore ks = null;
                    if (is != null) {
                        try {
                            KeyStore ksTry = KeyStore.getInstance("JCEKS");
                            ksTry.load(is, pwd.toCharArray());
                            ks = ksTry;
                        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
                            //e.printStackTrace();
                        }
                    }
                    if (ks != null) {
                        System.out.println("opened");
                        this.fileKeyStore.setText(fileChooserKeyStore.getSelectedFile().getName());
                        this.ks = ks;
                    }
                    else {
                        JOptionPane.showMessageDialog(this, "Wrong password or file format.", "KeyStore opening failed", JOptionPane.ERROR_MESSAGE);
                        fileChooserKeyStore.setSelectedFile(null);
                    }
                }
                break;
            default:break;
        }
        if (fileChooserKeyStore.getSelectedFile() != null ||
                (fileChooserCertificate.getSelectedFile() != null && fileChooserKeys.getSelectedFile() != null)) {
            this.searchButton.setEnabled(true);
        }
    }

    /**
     * Asks for the type of export the user wants for the given certificate
     * @param certificate the certificate to export
     */
    public void exportCertificate(X509Certificate certificate) {
        String[] options = {"Add in KeyStore", "Export in file"};
        int response = JOptionPane.showOptionDialog(this, "Certificate found !", "Certificate found", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        switch (response) {
            case 0:
                System.out.println("Add in KeyStore");
                addCertificateToKeyStore(certificate);
                break;
            case 1:
                System.out.println("Export in file");
                copyCertificateToFile(certificate);
                break;
            default:
                break;
        }
    }

    /**
     *
     * @param certificates
     */
    public void exportCertificates(List<X509Certificate> certificates) {
        int number = certificates.size();
        String[] options = {"Add in KeyStore", "Export in file"};
        int response = JOptionPane.showOptionDialog(this, number + " certificate(s) found !", "Certificate found", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        switch (response) {
            case 0:
                System.out.println("Add in KeyStore");
                for (X509Certificate c : certificates) {
                    addCertificateToKeyStore(c);
                }
                break;
            case 1:
                System.out.println("Export in file");
                for (X509Certificate c : certificates) {
                    copyCertificateToFile(c);
                }
                break;
            default:
                break;
        }
    }

    /**
     * Asks for an existing KeyStore file (and password) and saves the given certificate in it (with alias and password asked)
     * @param certificate the certificate to add
     */
    private void addCertificateToKeyStore(X509Certificate certificate) {
        JFileChooser fileChooserKeyStore = new JFileChooser(System.getProperty("user.dir"));
        fileChooserKeyStore.showOpenDialog(this);
        if (fileChooserKeyStore.getSelectedFile() != null) {
            String pwd = JOptionPane.showInputDialog("Password : ");
            InputStream is = null;
            try {
                is = new BufferedInputStream(new FileInputStream(fileChooserKeyStore.getSelectedFile()));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            KeyStore ks2 = null;
            if (is != null) {
                try {
                    KeyStore ksTry = KeyStore.getInstance("JCEKS");
                    ksTry.load(is, pwd.toCharArray());
                    ks2 = ksTry;
                } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
                    e.printStackTrace();
                }
            }
            if (ks2 != null) {
                String aliasName = JOptionPane.showInputDialog("Alias name : ");
                String pwdEntry = JOptionPane.showInputDialog("Set password : ");
                try {
                    X509Certificate[] certChain = new X509Certificate[1];
                    certChain[0] = certificate;
                    ks2.setKeyEntry(aliasName, privateKey, pwdEntry.toCharArray(), certChain);
                    OutputStream os = new BufferedOutputStream(new FileOutputStream(fileChooserKeyStore.getSelectedFile()));
                    ks2.store(os, pwd.toCharArray());
                    System.out.println("Certificate added");
                } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
                    e.printStackTrace();
                }
            } else {
                JOptionPane.showMessageDialog(this, "Wrong password or file format.", "KeyStore opening failed", JOptionPane.ERROR_MESSAGE);
            }
        }
        fileChooserKeyStore.setSelectedFile(null);
        privateKey = null;
    }

    /**
     * Generates a certificate file (.cer) from the given certificate
     * @param certificate the certificate to save as a file
     */
    private void copyCertificateToFile(X509Certificate certificate) {
        String fileName = JOptionPane.showInputDialog("File name : ");
        FileOutputStream fileWrite = null;
        try {
            fileWrite = new FileOutputStream(fileName + ".cer");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            assert fileWrite != null;
            fileWrite.write(certificate.getEncoded());
        } catch (IOException | CertificateEncodingException e) {
            e.printStackTrace();
        }
        try {
            fileWrite.flush();
            fileWrite.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}

