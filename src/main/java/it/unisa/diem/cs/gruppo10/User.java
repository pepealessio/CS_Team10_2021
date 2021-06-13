package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

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
     * The path keystore of the user.
     */
    private final String filepathTrustStore;

    /**
     * The password of the keystore
     */
    private final String passwordTrustStore;

    /**
     * Initialize an user, generate him PKFU and SKFU and his contact list empty.
     */
    public User(int port, String name, String filepathTruststore, String passwordTrustStore) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        this.port = port;
        this.name = name;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA");
        keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        this.keyPairF = keyGen.generateKeyPair();
        //this.userTrustStore = readStore(filepathTruststore, passwordTrustStore);
        this.filepathTrustStore = filepathTruststore;
        this.passwordTrustStore = passwordTrustStore;
        this.contacts = new ArrayList<>();
    }

    // In caso si debba caricare l'intero Keystore
    private KeyStore readStore(String filepath, String password) {
        try {

            InputStream stream = new FileInputStream(filepath);
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] trustStorePassword = password.toCharArray();
            store.load(stream, trustStorePassword);

            return store;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            //Handle error
            ex.printStackTrace();
            return null;
        }

    }

    /**
     * This method use two thread to simulate a contact exchange between two user.
     */
    public static void meet2user(User u1, User u2) throws InterruptedException {
        Thread u1tou2 = new Thread(() -> {
            try {
                u1.receiveContact();
                TimeUnit.MILLISECONDS.sleep(300);
                u1.sendContact(u2);
            } catch (Exception ignored) {
            }
        });

        Thread u2tou1 = new Thread(() -> {
            try {
                u2.sendContact(u1);
                u2.receiveContact();
            } catch (Exception ignored) {
            }
        });

        u1tou2.start();
        TimeUnit.MILLISECONDS.sleep(300);
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

    // Genera un thread che si occupa della comunicazione dei contatti
    public void communicatePositivity() throws IOException, KeyStoreException, InterruptedException {

        Thread startConnectionwithMD = new Thread(() -> {
            try {
                // Creazione Socket
                SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000);

                cSock.setEnabledCipherSuites(cSock.getSupportedCipherSuites());
                cSock.setEnabledProtocols(cSock.getSupportedProtocols());
                // Associazione del Truststore
                System.setProperty("javax.net.ssl.trustStore", filepathTrustStore);
                System.setProperty("javax.net.ssl.trustStorePassword", passwordTrustStore);

                System.out.println("Indirizzo: " + cSock.getRemoteSocketAddress());
                cSock.startHandshake();
                // Comunicazione positività
                ObjectOutputStream out = new ObjectOutputStream(cSock.getOutputStream());
                out.writeObject(contacts);
                cSock.close();
            } catch (Exception e) {
                System.out.println(e);
            }
        });
        startConnectionwithMD.start();
    }

    public void getNotify() throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
        // Obtain current ID
        byte[] id = getId();

        // Simulate connect to the MD server to read notify using a file
        ObjectInputStream in = new ObjectInputStream(new FileInputStream("contact_list.server"));
        ArrayList<byte[]> id_list = (ArrayList<byte[]>) in.readObject();
        for (byte[] c : id_list) {
            if (Arrays.equals(id, c)) {
                System.out.println(name + ": I've received a exposition notify.");
                return;
            }
        }
        System.out.println(name + ": I'm safe for now.");
    }

    private void sendContact(User u2) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u1 socket as pair BT request
        Socket clientSocket = new Socket("127.0.0.1", u2.getPort());
        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());

        // Now we simulate contact exchange ----------------------------------------------------
        // User 1 send message to user 2 as (2.6)
        ContactMessage c1to2 = new ContactMessage(keyPairF, u2.getId());
        out.writeObject(c1to2);

        // Simulate Two user close connection ------------------------------------------------
        out.close();
        clientSocket.close();
    }

    private void receiveContact() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u2 socket as pair BT accepting
        ServerSocket serverSocket = new ServerSocket(port);
        Socket clientSocket = serverSocket.accept();
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

        // Now we simulate contact exchange ----------------------------------------------------
        // Receive from u1
        ContactMessage c1to2 = (ContactMessage) in.readObject();
        if (c1to2.verifyBTPair(getId())) {
            System.out.println(name + ": I've added a contact");
            contacts.add(c1to2);
        } else {
            // If verify not have success
            System.out.println(name + ": I've REJECTED a contact");
        }

        // Simulate Two user close connection ------------------------------------------------
        in.close();
        clientSocket.close();
        serverSocket.close();
    }
}
