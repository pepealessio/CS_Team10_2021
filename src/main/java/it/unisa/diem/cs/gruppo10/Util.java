package it.unisa.diem.cs.gruppo10;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;

public class Util {
    public static String resourcesPath = "./src/main/resources/";

    public static Properties loadDefaultProperties() {
        return loadProperties("default.properties");
    }

    public static Properties loadProperties(String fileName) {
        Properties p = new Properties();
        try (FileReader reader = new FileReader(resourcesPath + fileName)) {
            p.load(reader);
        } catch (IOException e) {
            System.err.printf("Wrong path for \"%s\" file.\n", fileName);
            System.exit(1);
        }
        return p;
    }

    public static byte[] getIdFromPk(PublicKey pk) throws NoSuchAlgorithmException {
        byte[] pkByte = pk.getEncoded();
        MessageDigest h = MessageDigest.getInstance("SHA256");
        h.update(pkByte);
        return Arrays.copyOfRange(h.digest(), 0, 16);
    }

    public static TrustManagerFactory generateTrustStoreManager(String filePath, String password) throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        KeyStore ts = KeyStore.getInstance("JKS");
        char[] passTs = password.toCharArray();
        try {
            ts.load(new FileInputStream(filePath), passTs);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            System.err.println("Trust store not found!");
            System.exit(1);
        }
        tmf.init(ts);
        return tmf;
    }

    public static KeyManagerFactory generateKeyStoreManager(String filePath, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        KeyStore ks = KeyStore.getInstance("JKS");
        char[] passKs = password.toCharArray();
        try {
            ks.load(new FileInputStream(filePath), passKs);
        } catch (IOException | CertificateException e) {
            System.err.println("User key store not found!");
            System.exit(1);
        }
        kmf.init(ks, passKs);
        return kmf;
    }

}
