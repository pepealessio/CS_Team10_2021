package it.unisa.diem.cs.gruppo10;

import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
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
}
