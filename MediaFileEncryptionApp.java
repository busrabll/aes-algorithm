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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class MediaFileEncryptionApp extends JFrame {
    private JTextField selectedKeyImagePath;
    private JTextField selectedKeyAudioPath;
    private JTextField selectedFileForEncryptionPath;  // Şifrelemek için başka dosya
    private JTextArea encryptedTextArea;
    private JLabel decryptedImageLabel;
    private JButton playDecryptedAudioButton;
    private JComboBox<String> securityLevelComboBox; // Güvenlik seviyesi seçimi için
    private SecretKey encryptionKey; // Şifreleme için kullanılacak anahtar
    private SecretKey decryptionKey; // Şifre çözme için kullanılacak anahtar
    private boolean isAudioFile = false; // Ses dosyası mı, kontrol için
    private String currentSecurityLevel; // Mevcut güvenlik seviyesi (AES-128, AES-192, AES-256)
    private boolean isKeyGenerated = false;  // Anahtar oluşturulup oluşturulmadığını kontrol eden bayrak

    // Şifreleme ve şifre çözme anahtarlarını göstermek için alanlar
    private JTextArea encryptionKeyArea;
    private JTextArea decryptionKeyArea;

    public MediaFileEncryptionApp() {
        // GUI bileşenlerini oluştur
        setTitle("Media File Encryption App");
        setLayout(new FlowLayout());

        // Anahtar oluşturmak için kullanılacak dosyalar (görüntü ve ses)
        JButton selectKeyImageButton = new JButton("Anahtar için Görüntü Dosyası Seç");
        selectedKeyImagePath = new JTextField(30);
        add(selectKeyImageButton);
        add(selectedKeyImagePath);

        JButton selectKeyAudioButton = new JButton("Anahtar için Ses Dosyası Seç");
        selectedKeyAudioPath = new JTextField(30);
        add(selectKeyAudioButton);
        add(selectedKeyAudioPath);

        // Şifreleme için başka dosya seçimi (görsel ya da ses)
        JButton selectFileForEncryptionButton = new JButton("Şifrelenecek Dosyayı Seç");
        selectedFileForEncryptionPath = new JTextField(30);
        add(selectFileForEncryptionButton);
        add(selectedFileForEncryptionPath);

        // Güvenlik seviyesi seçimi
        String[] securityLevels = {"AES-128", "AES-192", "AES-256"};
        securityLevelComboBox = new JComboBox<>(securityLevels);
        add(new JLabel("Güvenlik Seviyesi Seçin:"));
        add(securityLevelComboBox);

        // Şifreleme anahtar üret butonu
        JButton generateEncryptionKeyButton = new JButton("Şifreleme için Anahtar Üret");
        add(generateEncryptionKeyButton);

        // Şifre çözme anahtar üret butonu
        JButton generateDecryptionKeyButton = new JButton("Şifre Çözme için Anahtar Üret");
        add(generateDecryptionKeyButton);

        // Şifreleme anahtarını göstermek için alan
        encryptionKeyArea = new JTextArea(2, 30);
        add(new JLabel("Şifreleme Anahtarı:"));
        add(new JScrollPane(encryptionKeyArea));

        // Şifre çözme anahtarını göstermek için alan
        decryptionKeyArea = new JTextArea(2, 30);
        add(new JLabel("Şifre Çözme Anahtarı:"));
        add(new JScrollPane(decryptionKeyArea));

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

        // Güvenlik seviyesi değiştiğinde butonları ve görselleri sıfırla
        securityLevelComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (isKeyGenerated) {
                    resetUI();  // Eğer anahtar üretildiyse, sıfırla ve uyarı ver
                    JOptionPane.showMessageDialog(null, 
                        "Güvenlik seviyesi " + securityLevelComboBox.getSelectedItem() + " olarak değiştirildi. " +
                        "Lütfen bu güvenlik seviyesi için yeni bir anahtar oluşturun.", 
                        "Uyarı", JOptionPane.WARNING_MESSAGE);
                }
                currentSecurityLevel = (String) securityLevelComboBox.getSelectedItem();  // Güvenlik seviyesini kaydet
            }
        });

        // Butonlar için event (olay) ekle
        selectKeyImageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFile(selectedKeyImagePath, "Anahtar için Görüntü Dosyası Seç");
            }
        });

        selectKeyAudioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFile(selectedKeyAudioPath, "Anahtar için Ses Dosyası Seç");
            }
        });

        selectFileForEncryptionButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFile(selectedFileForEncryptionPath, "Şifrelenecek Dosyayı Seç");
            }
        });

        generateEncryptionKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    encryptionKey = generateKeyFromFiles();  // Şifreleme için anahtar üret
                    encryptionKeyArea.setText(keyToBase64(encryptionKey)); // Şifreleme anahtarını ekranda göster
                    isKeyGenerated = true;  // Anahtar üretildi bayrağını işaretle
                    JOptionPane.showMessageDialog(null, "Şifreleme için anahtar başarıyla üretildi.");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Anahtar üretimi sırasında hata oluştu!");
                }
            }
        });

        generateDecryptionKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    decryptionKey = generateKeyFromFiles();  // Şifre çözme için anahtar üret
                    decryptionKeyArea.setText(keyToBase64(decryptionKey)); // Şifre çözme anahtarını ekranda göster
                    isKeyGenerated = true;  // Anahtar üretildi bayrağını işaretle
                    JOptionPane.showMessageDialog(null, "Şifre çözme için anahtar başarıyla üretildi.");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Anahtar üretimi sırasında hata oluştu!");
                }
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    // Şifrelenecek dosya yolunu kontrol et
                    if (selectedFileForEncryptionPath.getText().isEmpty()) {
                        throw new Exception("Şifrelenecek dosya seçilmedi!");
                    }
                    if (!isValidKeyForSelectedSecurityLevel(encryptionKey)) {
                        throw new Exception("Seçilen güvenlik seviyesi için geçerli bir anahtar oluşturulmadı!");
                    }
                    encryptFile();  // Şifreleme işlemi
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Şifreleme işlemi sırasında hata oluştu: " + ex.getMessage());
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    if (!isValidKeyForSelectedSecurityLevel(decryptionKey)) {
                        throw new Exception("Seçilen güvenlik seviyesi için geçerli bir anahtar oluşturulmadı!");
                    }
                    decryptFile();  // Şifre çözme işlemi
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Şifre çözme işlemi sırasında hata oluştu:" + ex.getMessage());
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

        setSize(600, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
    }

    // Dosya seçimi için JFileChooser kullan
    private void selectFile(JTextField textField, String dialogTitle) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(dialogTitle);
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            textField.setText(selectedFile.getAbsolutePath());

            // Eğer ses dosyasıysa, kontrol et
            String fileName = selectedFile.getName().toLowerCase();
            if (fileName.endsWith(".wav") || fileName.endsWith(".mp3") || fileName.endsWith(".m4a")) {
                isAudioFile = true;
            } else {
                isAudioFile = false;
            }
        }
    }

    // İki dosyadan anahtar üretimi (görüntü ve ses dosyasından hash üreterek)
    private SecretKey generateKeyFromFiles() throws Exception {
        String imagePath = selectedKeyImagePath.getText();
        String audioPath = selectedKeyAudioPath.getText();
        if (imagePath.isEmpty() || audioPath.isEmpty()) {
            throw new Exception("Lütfen hem görüntü hem de ses dosyasını seçin.");
        }

        // Görüntü ve ses dosyalarını oku
        byte[] imageBytes = Files.readAllBytes(new File(imagePath).toPath());
        byte[] audioBytes = Files.readAllBytes(new File(audioPath).toPath());

        // Görüntü ve ses dosyasını birleştir
        byte[] combinedBytes = new byte[imageBytes.length + audioBytes.length];
        System.arraycopy(imageBytes, 0, combinedBytes, 0, imageBytes.length);
        System.arraycopy(audioBytes, 0, combinedBytes, imageBytes.length, audioBytes.length);

        // SHA-256 hash üret (görüntü ve ses dosyasından)
        MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = shaDigest.digest(combinedBytes);

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
        return new SecretKeySpec(keyBytes, "AES");
    }

    // SecretKey'i Base64 stringe dönüştürmek
    private String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Seçilen güvenlik seviyesiyle ilgili geçerli bir anahtarın oluşturulup oluşturulmadığını kontrol eder
    private boolean isValidKeyForSelectedSecurityLevel(SecretKey key) {
        if (key == null) {
            return false;
        }
        String selectedSecurityLevel = (String) securityLevelComboBox.getSelectedItem();
        int requiredKeySize = 16; // Default AES-128
        if ("AES-192".equals(selectedSecurityLevel)) {
            requiredKeySize = 24;
        } else if ("AES-256".equals(selectedSecurityLevel)) {
            requiredKeySize = 32;
        }
        return key.getEncoded().length == requiredKeySize;
    }

    // Güvenlik seviyesi değiştirildiğinde butonları ve görselleri sıfırla
    private void resetUI() {
        // Daha önce aktif olan butonları ve görselleri sıfırla
        decryptedImageLabel.setIcon(null);
        decryptedImageLabel.setText("Çözülmüş görüntü burada görünecek");
        playDecryptedAudioButton.setEnabled(false);
        encryptedTextArea.setText("");
        encryptionKeyArea.setText("");
        decryptionKeyArea.setText("");
        isKeyGenerated = false;  // Anahtarlar sıfırlandı, anahtar üretim bayrağını sıfırla
    }

    // Şifreleme işlemi
    private void encryptFile() throws Exception {
        if (encryptionKey == null) {
            throw new Exception("Lütfen önce şifreleme için anahtar üretin.");
        }
        String filePath = selectedFileForEncryptionPath.getText();  // Şifreleme işlemi için farklı dosya kullan
        byte[] fileBytes = Files.readAllBytes(new File(filePath).toPath());

        // Rastgele IV oluştur
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);  // Güvenli IV üret
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivspec);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        // IV'yi ve şifrelenmiş veriyi birleştir
        byte[] combinedData = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combinedData, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combinedData, iv.length, encryptedBytes.length);

        // Şifrelenmiş veriyi Base64 formatına çevir ve textarea'ya yaz
        String encryptedData = Base64.getEncoder().encodeToString(combinedData);
        encryptedTextArea.setText(encryptedData);

        JOptionPane.showMessageDialog(null, "Şifreleme işlemi tamamlandı.");
    }

    // Şifre çözme işlemi
    private void decryptFile() throws Exception {
        if (decryptionKey == null) {
            throw new Exception("Lütfen önce şifre çözme için anahtar üretin.");
        }
        String encryptedData = encryptedTextArea.getText();
        byte[] combinedData = Base64.getDecoder().decode(encryptedData);

        // IV'yi şifrelenmiş veriden çıkar
        byte[] iv = Arrays.copyOfRange(combinedData, 0, 16);
        byte[] encryptedBytes = Arrays.copyOfRange(combinedData, 16, combinedData.length);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivspec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Eğer ses dosyasıysa, ses dosyasını geçici olarak sakla
        if (isAudioFile) {
            File tempFile = new File("decrypted_audio.wav");
            Files.write(tempFile.toPath(), decryptedBytes);
            JOptionPane.showMessageDialog(null, "Şifre çözme işlemi tamamlandı, sesi çalabilirsiniz.");
            playDecryptedAudioButton.setEnabled(true); // Şifre çözülmüş ses dosyasını çal butonunu aktif hale getir
        } else {
            // Eğer görüntü dosyasıysa, görüntüyü göster
            ImageIcon imageIcon = new ImageIcon(decryptedBytes);
            decryptedImageLabel.setIcon(imageIcon);
            decryptedImageLabel.setText("");
            playDecryptedAudioButton.setEnabled(false);
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
