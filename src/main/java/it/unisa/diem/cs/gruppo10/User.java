package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Ths class is used to simulate an user in the CT system.
 */
public class User implements Serializable {

    /**
     * TCP port to simulate BT connection.
     */
    private final int port;

    /**
     * The user name.
     */
    private final String name;

    /**
     * The ephemeral PK, SK value.
     */
    private final KeyPair keyPairF;

    /**
     * This list simulate the contact list.
     */
    List<ContactMessage> contacts;

    /**
     * Initialize an user, generate him PKFU and SKFU and his contact list empty.
     */
    public User(int port, String name) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        this.port = port;
        this.name = name;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA");
        keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        this.keyPairF = keyGen.generateKeyPair();

        this.contacts = new ArrayList<>();
    }

    /**
     * This method use two thread to simulate a contact exchange between two user.
     */
    public static void meet2user(User u1, User u2) throws InterruptedException {
        Thread u1tou2 = new Thread(() -> {
            try {
                u2.receiveContact(u1);
            } catch (Exception ignored) {
            }
        });

        Thread u2tou1 = new Thread(() -> {
            try {
                u1.sendContact(u2);
            } catch (Exception ignored) {
            }
        });

        u1tou2.start();
        u2tou1.start();

        u1tou2.join();
        u2tou1.join();
    }

    /**
     * Getter method for port.
     */
    public int getPort() {
        return port;
    }

    /**
     * Evaluate ID with 2.4 formula.
     */
    public byte[] getId() throws NoSuchAlgorithmException {
        byte[] pkfuByte = keyPairF.getPublic().getEncoded();
        MessageDigest h = MessageDigest.getInstance("SHA256");
        h.update(pkfuByte);
        return Arrays.copyOfRange(h.digest(), 0, 16);
    }

    /**
     * The ephemeral PK, SK value getter.
     */
    public KeyPair getKeyPairF() {
        return keyPairF;
    }

    private void sendContact(User u2) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u1 soket as pair BT request
        Socket clientSocket = new Socket("127.0.0.1", u2.getPort());
        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

        // Now we simulate contact excange ----------------------------------------------------
        // User 1 send message to user 2 as (2.6)
        ContactMessage c1to2 = new ContactMessage(keyPairF, u2.getId());
        out.writeObject(c1to2);

        try {
            ContactMessage c2to1 = (ContactMessage) in.readObject();
            if (c2to1.verify(getId())) {
                System.out.println(name + ": I've added a contact");
                contacts.add(c2to1);
            } else {
                // If verify not have success
                System.out.println(name + ": I've REJECTED a contact");
            }
        } catch (ClassNotFoundException ignored) {
        }

        // Simulate Two user close connection ------------------------------------------------
        in.close();
        out.close();
        clientSocket.close();
    }

    private void receiveContact(User u1) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u2 soket as pair BT accepting
        ServerSocket serverSocket = new ServerSocket(port);
        Socket clientSocket = serverSocket.accept();
        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

        // Now we simulate contact excange ----------------------------------------------------
        // Recive from u1
        ContactMessage c1to2 = (ContactMessage) in.readObject();
        if (c1to2.verify(getId())) {
            System.out.println(name + ": I've added a contact");
            contacts.add(c1to2);

            // If verify have success
            ContactMessage c2to1 = new ContactMessage(keyPairF, u1.getId());
            out.writeObject(c2to1);

        } else {
            // If verify not have success
            System.out.println(name + ": I've REJECTED a contact");
        }

        // Simulate Two user close connection ------------------------------------------------
        in.close();
        out.close();
        clientSocket.close();
        serverSocket.close();
    }

    private void communicatePositivity()
    {

    }

    private void getNotify()
    {

    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        Security.addProvider(new BouncyCastleProvider());

        User teresa = new User(5600, "Teresa");
        User paolo = new User(5601, "Paolo");
        User alessio = new User(5602, "Alessio");
        User luigi = new User(5603, "Luigi");

        System.out.println("Teresa -> Paolo");
        meet2user(teresa, paolo);
        System.out.println("Alessio -> Paolo");
        meet2user(alessio, paolo);
        System.out.println("Teresa -> Luigi");
        meet2user(teresa, luigi);
        System.out.println("Paolo -> Luigi");
        meet2user(paolo, luigi);

        System.out.println(teresa.contacts.size() + alessio.contacts.size() + paolo.contacts.size() + luigi.contacts.size());
    }
}
