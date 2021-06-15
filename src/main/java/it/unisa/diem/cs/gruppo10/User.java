package it.unisa.diem.cs.gruppo10;

import com.sun.tools.javac.Main;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * Ths class is used to simulate an user in the CT system.
 */
public class User implements Serializable {

    private final String name;
    private final TrustManagerFactory tmf;
    private final KeyManagerFactory kmf;
    private final Properties userProperties;
    private final Properties defaultProperties;
    private KeyPair keyPair;
    private KeyPair keyPairF;
    List<ContactMessage> contacts;


    /**
     * Initialize an user, generate him PKFU and SKFU and his contact list empty.
     */
    public User(String name) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, UnrecoverableKeyException {
        this.name = name;

        // Read properties
        userProperties = Util.loadProperties("user.properties");
        defaultProperties = Util.loadDefaultProperties();

        // Read trust store
        tmf = Util.generateTrustStoreManager(Util.resourcesPath + userProperties.getProperty("trustStoreFile"),
                userProperties.getProperty("trustStorePassword"));

        // Read Key Store
        kmf = Util.generateKeyStoreManager(Util.resourcesPath + userProperties.getProperty(name + ".keyStoreFile"),
                userProperties.getProperty(name + ".keyStorePassword"));

        // Read Certificated KeyPair
        keyPair = Util.readKpFromKeyStore(Util.resourcesPath + userProperties.getProperty(name + ".keyStoreFile"),
                userProperties.getProperty(name + ".keyStorePassword"), name);

        // Init empty contact List
        this.contacts = new ArrayList<>();
    }

    /**
     * This method use two thread to simulate a contact exchange between two user.
     */
    public static void meet2user(User u1, User u2) throws InterruptedException {
        System.out.println(u1.name + " -> " + u2.name);

        Thread u1tou2 = new Thread(() -> {
            try {
                u1.receiveContact();
                TimeUnit.MILLISECONDS.sleep(100);
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
        TimeUnit.MILLISECONDS.sleep(100);
        u2tou1.start();

        u1tou2.join();
        u2tou1.join();
    }


    /**
     * Evaluate ID with 2.4 formula.
     */
    public byte[] getId() throws NoSuchAlgorithmException {
        return Util.getIdFromPk(keyPairF.getPublic());
    }

    public void generateEphemeralKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyManagementException {
        // Generate PKf
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA");
        keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        this.keyPairF = keyGen.generateKeyPair();

        SecureRandom random = new SecureRandom();
        byte[] r = new byte[256];
        random.nextBytes(r);
        PkfCommitment commitment = new PkfCommitment(r, keyPair.getPublic(), keyPairF.getPublic(), LocalDate.now());

        // Creazione Socket
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        SSLSocketFactory factory = ctx.getSocketFactory();
        try (SSLSocket cSock = (SSLSocket) factory.createSocket("localhost",
                Integer.parseInt(defaultProperties.getProperty("MDTlsSocketReceiveCommitment")))) {
            // Handshake
            cSock.startHandshake();
            try (ObjectOutputStream out = new ObjectOutputStream(cSock.getOutputStream())) {
                out.writeObject(commitment.getCommitment());
                TimeUnit.MILLISECONDS.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(7);
        }
    }

    // Genera un thread che si occupa della comunicazione dei contatti
    public void communicatePositivity() throws NoSuchAlgorithmException, KeyManagementException, IOException {
        // Context Creation
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());

        // Creazione Socket
        SSLSocketFactory factory = ctx.getSocketFactory();
        SSLSocket cSock = (SSLSocket) factory.createSocket("localhost", Integer.parseInt(userProperties.getProperty("MDTlsSocketReceiveContacts")));

        // Handshake
        cSock.startHandshake();

        // Comunicazione positività
        try (ObjectOutputStream out = new ObjectOutputStream(cSock.getOutputStream())) {
            out.writeObject(keyPairF.getPublic());
            out.writeObject(contacts);
        }

        // Chiusura comunicazione
        cSock.close();
    }

    public void getNotify() throws NoSuchAlgorithmException, IOException, ClassNotFoundException, KeyManagementException {
        // Obtain current ID
        byte[] id = getId();

        // Context Creation
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Creazione Socket
        SSLSocketFactory factory = ctx.getSocketFactory();
        SSLSocket cSock = (SSLSocket) factory.createSocket("localhost", Integer.parseInt(userProperties.getProperty("MDTlsSocketSendRiskId")));

        // Handshake
        cSock.startHandshake();

        // Lettura Positività
        ArrayList<byte[]> idList;
        try (ObjectInputStream in = new ObjectInputStream(cSock.getInputStream())) {
            idList = (ArrayList<byte[]>) in.readObject();
        }

        // Chiusura comunicazione
        cSock.close();

        // Check my ID presence
        for (byte[] c : idList) {
            if (Arrays.equals(id, c)) {
                System.out.println(name + ": I've received a exposition notify.");
                return;
            }
        }
    }

    private void sendContact(User u2) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u1 socket as pair BT request
        try (Socket clientSocket = new Socket("localhost", Integer.parseInt(userProperties.getProperty("BTSimulatePort")))) {
            try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {

                // Now we simulate contact exchange ----------------------------------------------------
                // User 1 send message to user 2 as (2.6)
                ContactMessage c1to2 = new ContactMessage(keyPairF, u2.getId());
                out.writeObject(c1to2);
            }
        }
    }

    private void receiveContact() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u2 socket as pair BT accepting
        try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(userProperties.getProperty("BTSimulatePort")))) {
            try (Socket clientSocket = serverSocket.accept()) {
                try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

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
                }
            }
        }
    }
}
