package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;

public class MainSimulation {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException, IOException, ClassNotFoundException {
        Security.addProvider(new BouncyCastleProvider());

        // Initializate the user as the phase 2.3.1 -------------------------------------------------------------------
        User teresa = new User(5600, "Teresa");
        User paolo = new User(5601, "Paolo");
        User alessio = new User(5602, "Alessio");
        User luigi = new User(5603, "Luigi");

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

        // Teresa communicate positivity like figure 1.1 --------------------------------------------------------------

        //////////// REPLACE WITH SSL ////////////////////////////
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("contact_list.server"));
        ArrayList<byte[]> lis = new ArrayList<>();
        lis.add(paolo.getId());
        lis.add(luigi.getId());
        out.writeObject(lis);
        out.close();
        //////////// REPLACE WITH SSL ////////////////////////////

        // User attempts for a notify
        teresa.getNotify();
        paolo.getNotify();
        alessio.getNotify();
        luigi.getNotify();
    }
}
