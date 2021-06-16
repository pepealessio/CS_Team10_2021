package it.unisa.diem.cs.gruppo10;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Ths class is used to simulate an user in the CT system.
 */
public class User {

    private final String name;
    private final TrustManagerFactory tmf;
    private final KeyManagerFactory kmf;
    private final Properties userProperties;
    private final Properties defaultProperties;
    private final KeyPair keyPair;
    private KeyPair keyPairF;
    private PkfCommitment com;
    List<ContactMessage> contacts;


    /**
     * Initialize an user.
     */
    public User(String name) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
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
        System.out.println(u1.name + " -> " + u2.name + " and " + u2.name + " -> " + u1.name);

        Thread u1tou2 = new Thread(() -> {
            try {
                u1.receiveContact(u2);
            } catch (Exception ignored) {
            }
        });

        Thread u2tou1 = new Thread(() -> {
            try {
                u2.sendContact(u1);
            } catch (Exception e) {
                e.printStackTrace();
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

    public String getName() {
        return name;
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    /**
     * Described in 4.3.1
     * Method used to generate the KeyPair described in (2.2). In this method a TLS connection with the MD server is
     * also established to commit the key
     */
    public void generateEphemeralKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyManagementException {
        // Generate PKf
        System.out.println(name + ": I'm generating a ephemeral key.");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA");
        keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        this.keyPairF = keyGen.generateKeyPair();


        SecureRandom random = new SecureRandom();
        byte[] r = new byte[256];
        random.nextBytes(r);
        PkfCommitment commitment = new PkfCommitment(r, keyPair.getPublic(), keyPairF.getPublic(), LocalDate.now());

        // Save commitment
        com = commitment;

        // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
        System.out.println(name + ": Now I'm committing the ephemeral key.");
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Instantiation of the SSLSocket
        SSLSocketFactory factory = ctx.getSocketFactory();
        try (SSLSocket cSock = (SSLSocket) factory.createSocket("localhost",
                Integer.parseInt(defaultProperties.getProperty("MDTlsSocketReceiveCommitment")))) {
            // Handshake request to start the connection
            cSock.startHandshake();
            // Opening of a Stream for the communication with server
            try (ObjectOutputStream out = new ObjectOutputStream(cSock.getOutputStream())) {
                out.writeObject(commitment.getCommitment());
                TimeUnit.MILLISECONDS.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Described in 4.4.2 and 4.4.3
     * This method establishes a TLS connection with the HA Server to request an HAToken related to the pk sent.
     * Upon receiving it, the token is provided to the MD in another TLS connection, and eventually all the contacts
     * are communicated to the MD
     */
    public void communicatePositivity() throws Exception {
        System.out.println(name + ": I'm communicating my contacts because I'm positive!");
        System.out.println(name + ": Now I require a Token to HA");

        HAToken token;
        // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
        SSLContext ctx1 = SSLContext.getInstance("TLS");
        ctx1.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Instantiation of the SSLSocket
        SSLSocketFactory factory1 = ctx1.getSocketFactory();
        SSLSocket cSock1 = (SSLSocket) factory1.createSocket("localhost", Integer.parseInt(defaultProperties.getProperty("HATlsSReceiveToken")));

        // Handshake request to start the connection
        cSock1.startHandshake();

        // Opening of a Stream for the communication with the server
        try (ObjectOutputStream out1 = new ObjectOutputStream(cSock1.getOutputStream());
             ObjectInputStream in1 = new ObjectInputStream(cSock1.getInputStream())) {
            // Communication of the commitment and  receipt of the related token
            out1.writeObject(com);
            token = (HAToken) in1.readObject();
        }

        // Closing communication
        cSock1.close();

        // ----------------------- Now sends contact to MD ------------------------------------------------
        System.out.println(name + ": Now I send my contact to MD with my token");
        // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
        SSLContext ctx2 = SSLContext.getInstance("TLS");
        ctx2.init(null, tmf.getTrustManagers(), new SecureRandom());

        // Instantiation of the SSLSocket
        SSLSocketFactory factory2 = ctx2.getSocketFactory();
        SSLSocket cSock2 = (SSLSocket) factory2.createSocket("localhost", Integer.parseInt(defaultProperties.getProperty("MDTlsSocketReceiveContacts")));

        // Handshake request to start the communication
        cSock2.startHandshake();

        // Opening of a Stream for the connection with server
        try (ObjectOutputStream out2 = new ObjectOutputStream(cSock2.getOutputStream())) {
            // the token is sent to be authorized in sending the contacts
            out2.writeObject(token);
            out2.writeObject(contacts);
        }

        // Closing communication
        cSock2.close();
    }

    /**
     * Described in 4.5.1
     * This method establishes a TLS connection with the MD Server to download the list of all the IDs at risk and check
     * if the user's ID is present among these.
     */
    public byte[] getNotify() throws NoSuchAlgorithmException, IOException, ClassNotFoundException, KeyManagementException {
        System.out.println("\n" + name + ": Now I check for notify");

        // Obtain current ID
        byte[] id = getId();

        // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Instantiation of the SSLSocket
        SSLSocketFactory factory = ctx.getSocketFactory();
        SSLSocket cSock = (SSLSocket) factory.createSocket("localhost", Integer.parseInt(defaultProperties.getProperty("MDTlsSocketSendRiskId")));

        // Handshake request to start the connection
        cSock.startHandshake();

        ArrayList<byte[]> idList;
        // Opening of a Stream for the communication with the server
        try (ObjectInputStream in = new ObjectInputStream(cSock.getInputStream())) {
            // Download of the list od IDs at risk
            idList = (ArrayList<byte[]>) in.readObject();
        }

        // Closing communication
        cSock.close();

        // Check if my ID if present among the IDs at risk
        for (byte[] c : idList) {
            if (Arrays.equals(id, c)) {
                System.out.println(name + ": I've received an exposition notification.");
                return c;
            }
        }
        return null;
    }

    /**
     * Described in 4.5.2
     * This method establishes a TLS connection with the HA Server. If the ID passed as input is present among the risk
     * contact, it books a swab. This will be free only if the request took place less then 24h after the reception of
     * the risk notification.
     */
    public void bookSwab(byte[] id) throws Exception {

        System.out.println(name + ": I want to book a swab because I had a contact");

        // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Instantiation of the SSLSocket
        SSLSocketFactory factory = ctx.getSocketFactory();
        SSLSocket cSock = (SSLSocket) factory.createSocket("localhost", Integer.parseInt(defaultProperties.getProperty("HATlsBookSwab")));

        // Handshake request to start the connection
        cSock.startHandshake();

        // Opening of a Stream for the communication with server
        try (ObjectOutputStream out = new ObjectOutputStream(cSock.getOutputStream())) {
            // Sending the ID received from the notification
            out.writeObject(com);
            TimeUnit.MILLISECONDS.sleep(2000);
        }

        // Closing communication
        cSock.close();
    }

    /**
     * Described in 4.3.2
     * Simulation of sending part of a Bluetooth pairing
     */
    private void sendContact(User u2) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u1 socket as pair BT request
        try (Socket clientSocket = new Socket("localhost", Integer.parseInt(userProperties.getProperty("BTSimulatePort")))) {
            try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                 ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

                // Now we simulate contact exchange ----------------------------------------------------
                // User 1 send message to user 2 as (2.6)
                ContactMessage c1to2 = new ContactMessage(keyPairF, u2.getId());
                out.writeObject(c1to2);

                ContactMessage c2to1 = (ContactMessage) in.readObject();
                if (c2to1.verifyBTPair(getId())) {
                    System.out.println(name + ": I've added a contact");
                    contacts.add(c2to1);
                } else {
                    // If verify not have success
                    System.out.println(name + ": I've REJECTED a contact");
                }
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Described in 4.3.2
     * Simulation of receiving part of a Bluetooth pairing
     */
    private void receiveContact(User u1) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // SIMULATE PAIRING ------------------------------------------------------------------
        // Start u2 socket as pair BT accepting
        try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(userProperties.getProperty("BTSimulatePort")))) {
            try (Socket clientSocket = serverSocket.accept()) {
                try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
                     ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {

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

                    ContactMessage c2to1 = new ContactMessage(keyPairF, u1.getId());
                    out.writeObject(c2to1);
                }
            }
        }
    }
}
