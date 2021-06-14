package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class MainSimulation {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException, IOException, ClassNotFoundException, KeyStoreException {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("\n\nSimulate phase 2.1. -----------------------\n");
        MD md = new MD(4000, "mdkeystore.jks", "ubuntu");
        md.connection_MD();
        TimeUnit.SECONDS.sleep(1);

        System.out.println("\n\nSimulate phase 2.3.1 -----------------------\n");
        User teresa = new User(5600, "Teresa", "publictruststore.jks", "ubuntu");
        User paolo = new User(5601, "Paolo", "publictruststore.jks", "ubuntu");
        User alessio = new User(5602, "Alessio","publictruststore.jks", "ubuntu");
        User luigi = new User(5603, "Luigi", "publictruststore.jks", "ubuntu");

        System.out.println("\n\nSimulate phase 2.3.3 -----------------------\n");
        // Simulate BT contact exchange like figure 1.1 with TCP connection and thread. -------------------------------
        System.out.println("Teresa -> Paolo");
        User.meet2user(teresa, paolo);
        System.out.println("Alessio -> Paolo");
        User.meet2user(alessio, paolo);
        System.out.println("Teresa -> Luigi");
        User.meet2user(teresa, luigi);
        System.out.println("Paolo -> Luigi");
        User.meet2user(paolo, luigi);
        // System.out.println(teresa.contacts.size() + alessio.contacts.size() + paolo.contacts.size() + luigi.contacts.size());

        System.out.println("\n\nSimulate phase 2.4-----------------------\n");
        // Teresa communicate positivity like figure 1.1 --------------------------------------------------------------
        teresa.communicatePositivity(md.getPort());
        TimeUnit.SECONDS.sleep(1);

        System.out.println("\n\nSimulate phase 2.5 -----------------------\n");
        teresa.getNotify();
        paolo.getNotify();
        alessio.getNotify();
        luigi.getNotify();
    }
}
