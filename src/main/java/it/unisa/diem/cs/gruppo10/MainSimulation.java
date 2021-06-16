package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.concurrent.TimeUnit;

public class MainSimulation {
    public static void main(String[] args) throws Exception {
        // Add crypto Provider
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("\n\nSimulate phase 2.1. -----------------------\n");

        MD md = new MD();
        HA ha = new HA(md);
        TimeUnit.SECONDS.sleep(1);

        System.out.println("""


                Simulate phase 2.2. -----------------------
                User Certificate are provided externally.""");
        User teresa = new User("Teresa");
        User paolo = new User("Paolo");
        User alessio = new User("Alessio");
        User luigi = new User("Luigi");

        System.out.println("""


                Simulate phase 2.3.1 -----------------------
                User generate PKf""");
        teresa.generateEphemeralKey();
        paolo.generateEphemeralKey();
        luigi.generateEphemeralKey();
        alessio.generateEphemeralKey();

        System.out.println("\n\nSimulate phase 2.3.3 -----------------------\n");
        User.meet2user(teresa, paolo);
        User.meet2user(alessio, paolo);
        User.meet2user(teresa, luigi);
        User.meet2user(paolo, luigi);

        System.out.println("\n\nSimulate phase 2.4-----------------------\n" );
        ha.setPositive(teresa);
        teresa.communicatePositivity();
        TimeUnit.SECONDS.sleep(1);

        System.out.println("\n\nSimulate phase 2.5 -----------------------\n");
        byte[] id;
        id = teresa.getNotify();
        if (id != null) {
            teresa.bookSwab(id);
        }
        id = paolo.getNotify();
        if (id != null) {
            paolo.bookSwab(id);
        }
        id = alessio.getNotify();
        if (id != null) {
            alessio.bookSwab(id);
        }
        id = luigi.getNotify();
        if (id != null) {
            luigi.bookSwab(id);
        }
    }
}
