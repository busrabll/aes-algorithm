import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class MediaFileEncryptionApp extends JFrame {
    private JTextField selectedFilePath;
    private JTextArea encryptedTextArea;
    private JLabel decryptedImageLabel;
    private JButton playDecryptedAudioButton;
    private JComboBox<String> securityLevelComboBox; // Güvenlik seviyesi seçimi için
    private SecretKey aesKey;
    private boolean isAudioFile = false; // Ses dosyası mı, kontrol için
    private byte[] lastFileHash; // Aynı dosyanın kullanıldığını kontrol etmek için hash saklanacak

    public MediaFileEncryptionApp() {
        // GUI bileşenlerini oluştur
        setTitle("Media File Encryption App");
        setLayout(new FlowLayout());

        // Dosya seçme butonu
        JButton selectFileButton = new JButton("Dosya Seç (Görüntü/Ses)");
        selectedFilePath = new JTextField(30);
        add(selectFileButton);
        add(selectedFilePath);

        // Güvenlik seviyesi seçimi
        String[] securityLevels = {"AES-128", "AES-192", "AES-256"};
        securityLevelComboBox = new JComboBox<>(securityLevels);
        add(new JLabel("Güvenlik Seviyesi Seçin:"));
        add(securityLevelComboBox);

        // Anahtar üret butonu
        JButton generateKeyButton = new JButton("Anahtar Üret");
        add(generateKeyButton);

        // Şifreleme butonu
        JButton encryptButton = new JButton("Dosyayı Şifrele");
        add(encryptButton);

        // Şifrelenmiş veri gösterim alanı
        encryptedTextArea = new JTextArea(5, 30);
        add(new JScrollPane(encryptedTextArea));

        // Şifre çözme butonu
        JButton decryptButton = new JButton("Şifreyi Çöz");
        add(decryptButton);

        // Şifre çözülmüş görüntü gösterim alanı
        decryptedImageLabel = new JLabel("Çözülmüş görüntü burada görünecek");
        add(decryptedImageLabel);

        // Şifre çözülmüş ses dosyasını çalma butonu
        playDecryptedAudioButton = new JButton("Çözülen Sesi Çal");
        playDecryptedAudioButton.setEnabled(false);
        add(playDecryptedAudioButton);

        // Butonlar için event (olay) ekle
        selectFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFile();
            }
        });

        generateKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    generateKeyFromFile();  // Anahtar üretimi için görüntü/ses dosyasını kullan
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Anahtar üretimi sırasında hata oluştu!");
                }
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    encryptFile();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Şifreleme işlemi sırasında hata oluştu!");
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    decryptFile();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Şifre çözme işlemi sırasında hata oluştu!");
                }
            }
        });

        playDecryptedAudioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (isAudioFile) {
                    playDecryptedAudio();
                }
            }
        });

        setSize(500, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
    }

    // Dosya seçimi için JFileChooser kullan
    private void selectFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            selectedFilePath.setText(selectedFile.getAbsolutePath());

            // Dosyanın uzantısına bakarak görüntü mü ses mi olduğunu kontrol et
            String fileName = selectedFile.getName().toLowerCase();
            if (fileName.endsWith(".png") || fileName.endsWith(".jpg") || fileName.endsWith(".jpeg")) {
                isAudioFile = false;
                decryptedImageLabel.setText("Çözülmüş görüntü burada görünecek");
                playDecryptedAudioButton.setEnabled(false);
            } else if (fileName.endsWith(".wav") || fileName.endsWith(".mp3") || fileName.endsWith(".m4a")) {
                isAudioFile = true;
                decryptedImageLabel.setText("");
                playDecryptedAudioButton.setEnabled(true);
            } else {
                JOptionPane.showMessageDialog(null, "Desteklenmeyen dosya türü.");
            }
        }
    }

    // Dosyadan anahtar üretimi (görüntü/ses dosyasından hash üreterek)
    private void generateKeyFromFile() throws Exception {
        String filePath = selectedFilePath.getText();
        File file = new File(filePath);
        byte[] fileBytes = Files.readAllBytes(file.toPath());

        // SHA-256 hash üret (görüntü/ses dosyasından)
        MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = shaDigest.digest(fileBytes);

        // Güvenlik seviyesini seç (AES-128, AES-192, AES-256)
        String selectedSecurityLevel = (String) securityLevelComboBox.getSelectedItem();
        int keySize = 16; // Default AES-128
        if ("AES-192".equals(selectedSecurityLevel)) {
            keySize = 24; // AES-192 için 24 byte anahtar
        } else if ("AES-256".equals(selectedSecurityLevel)) {
            keySize = 32; // AES-256 için 32 byte anahtar
        }

        // Anahtarı doldurma (padding) ile belirtilen boyuta getir
        keyBytes = Arrays.copyOf(keyBytes, keySize);

        // AES anahtarını üret
        aesKey = new SecretKeySpec(keyBytes, "AES");

        JOptionPane.showMessageDialog(null, selectedSecurityLevel + " güvenlik seviyesinde anahtar başarıyla üretildi.");
    }

    // Şifreleme işlemi
    private void encryptFile() throws Exception {
        String filePath = selectedFilePath.getText();
        byte[] fileBytes = Files.readAllBytes(new File(filePath).toPath());

        byte[] iv = new byte[16]; // Basit IV değeri
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivspec);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        // Şifrelenmiş veriyi Base64 formatına çevir ve textarea'ya yaz
        String encryptedData = Base64.getEncoder().encodeToString(encryptedBytes);
        encryptedTextArea.setText(encryptedData);

        JOptionPane.showMessageDialog(null, "Şifreleme işlemi tamamlandı.");
    }

    // Şifre çözme işlemi
    private void decryptFile() throws Exception {
        String encryptedData = encryptedTextArea.getText();
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

        byte[] iv = new byte[16]; // Basit IV değeri
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivspec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Eğer görüntü dosyasıysa, görüntüyü göster
        if (!isAudioFile) {
            ImageIcon imageIcon = new ImageIcon(decryptedBytes);
            decryptedImageLabel.setIcon(imageIcon);
            decryptedImageLabel.setText("");
            playDecryptedAudioButton.setEnabled(false);
        } else {
            // Eğer ses dosyasıysa, ses dosyasını geçici olarak sakla
            File tempFile = new File("decrypted_audio.wav");
            Files.write(tempFile.toPath(), decryptedBytes);
            JOptionPane.showMessageDialog(null, "Şifre çözme işlemi tamamlandı, sesi çalabilirsiniz.");
            playDecryptedAudioButton.setEnabled(true);
        }
    }

    // Şifre çözülmüş ses dosyasını çalma
    private void playDecryptedAudio() {
        try {
            File soundFile = new File("decrypted_audio.wav");
            if (soundFile.exists()) {
                java.awt.Desktop.getDesktop().open(soundFile);  // Varsayılan ses oynatıcıyla çal
            } else {
                JOptionPane.showMessageDialog(null, "Çözülmüş ses dosyası bulunamadı.");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Ses çalınırken hata oluştu.");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new MediaFileEncryptionApp();
            }
        });
    }
}
