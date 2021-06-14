package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

public class MainSimulation {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException, IOException, ClassNotFoundException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("\n\nSimulate phase 2.1. -----------------------\n");
        MD md = new MD(4000, 4001, "mdkeystore.jks", "ubuntu","teresaTruststore.jks", "gruppo10");
        md.receiveContactMd();
        md.sendContactListMd();
        TimeUnit.SECONDS.sleep(1);

        System.out.println("\n\nSimulate phase 2.3.1 -----------------------\n");
        User teresa = new User(5600, "Teresa", "publictruststore.jks", "ubuntu","teresa.jks", "gruppo10");
        User paolo = new User(5601, "Paolo", "publictruststore.jks", "ubuntu","teresa.jks", "gruppo10");
        User alessio = new User(5602, "Alessio","publictruststore.jks", "ubuntu","teresa.jks", "gruppo10");
        User luigi = new User(5603, "Luigi", "publictruststore.jks", "ubuntu","teresa.jks", "gruppo10");

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
        teresa.getNotify(md.getPort2());
        paolo.getNotify(md.getPort2());
        alessio.getNotify(md.getPort2());
        luigi.getNotify(md.getPort2());
    }
}
