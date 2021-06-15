package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

public class MainSimulation {
    public static void main(String[] args) throws Exception {
        // Add crypto Provider
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("\n\nSimulate phase 2.1. -----------------------\n");
        MD md = new MD();
        TimeUnit.SECONDS.sleep(1);

        System.out.println("\n\nSimulate phase 2.2. -----------------------\n" +
                "User Certificate are provided externally.");
        User teresa = new User("Teresa");
        User paolo = new User("Paolo");
        User alessio = new User("Alessio");
        User luigi = new User("Luigi");

        System.out.println("\n\nSimulate phase 2.3.1 -----------------------\n" +
                "User generate PKf");
        teresa.generateEphemeralKey();
        paolo.generateEphemeralKey();
        luigi.generateEphemeralKey();
        alessio.generateEphemeralKey();

        System.out.println("\n\nSimulate phase 2.3.3 -----------------------\n");
        User.meet2user(teresa, paolo);
        User.meet2user(alessio, paolo);
        User.meet2user(teresa, luigi);
        User.meet2user(paolo, luigi);

        System.out.println("\n\nSimulate phase 2.4-----------------------\n" +
                "Now teresa communicate positivity");
        teresa.communicatePositivity();

        System.out.println("\n\nSimulate phase 2.5 -----------------------\n");
        teresa.getNotify();
        paolo.getNotify();
        alessio.getNotify();
        luigi.getNotify();
    }
}
