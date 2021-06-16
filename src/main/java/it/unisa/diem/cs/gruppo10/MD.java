package it.unisa.diem.cs.gruppo10;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Ths class is used to simulate the MD in the CT system.
 */
public class MD {
    private static class DateId {
        LocalDateTime dateTime;
        byte[] id;

        public DateId(byte[] id) {
            this.id = id;
            dateTime = LocalDateTime.now();
        }

        public byte[] getId() {
            return id;
        }

        public LocalDateTime getDateTime() {
            return dateTime;
        }
    }

    private final Properties defaultProperties;
    private final ArrayList<DateId> idContactMessage;
    private final TrustManagerFactory tmf;
    private final KeyManagerFactory kmf;
    private final HashMap<PublicKey, byte[]> commitments;

    public MD() throws Exception {
        Properties mdProperties = Util.loadProperties("md.properties");
        defaultProperties = Util.loadDefaultProperties();

        idContactMessage = new ArrayList<>();
        this.commitments = new HashMap<>();

        // Read trust store
        tmf = Util.generateTrustStoreManager(Util.resourcesPath + mdProperties.getProperty("trustStoreFile"),
                mdProperties.getProperty("trustStorePassword"));

        // Read Key Store
        kmf = Util.generateKeyStoreManager(Util.resourcesPath + mdProperties.getProperty("keyStoreFile"),
                mdProperties.getProperty("keyStorePassword"));

        // Starting of the Threads that simulate the servers
        receiveCommitmentMd();
        receiveContactMd();
        sendContactListMd();


        System.out.println("MD: Now I'm ready to receive authenticated contacts and to send ID lists. ");
    }

    public HashMap<PublicKey, byte[]> getCommitments() {
        return commitments;
    }

    /**
     * @return the list od IDs from a list of DateIds
     */
    private List<byte[]> getIds() {
        return idContactMessage.stream().map(MD.DateId::getId).collect(Collectors.toList());
    }

    /**
     * Runs through the list od DateIds and returns the date of the id passed as input
     *
     * @param id an id
     * @return the DateTime of the id passed as input
     */
    public LocalDateTime getDateTimeOfCommunicatedID(byte[] id) {
        for (DateId di : idContactMessage) {
            if (Arrays.equals(di.getId(), id)) {
                return di.getDateTime();
            }
        }
        return null;
    }

    /**
     * Described in 4.3.1
     * This method generates a Thread that simulates the MD's server that receives the commitments from the users and
     * store them in an HashTable, whose key is the Public key of the user, which represent a database of the MD
     */
    private void receiveCommitmentMd() {
        // Defining a thread to simulate the MD server.
        Thread receiveCommitmentThreadMd = new Thread(() -> {

            SSLContext ctx;
            try {
                // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                // Instantiation of the SSLServerSocket
                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket) factory.createServerSocket(Integer.parseInt(defaultProperties.getProperty("MDTlsSocketReceiveCommitment")));
                // This SSL connection requires the authentication of the client (Two Way Handshake)
                sSock.setNeedClientAuth(true);
                while (true) {

                    // Server's waiting for clients to connect
                    SSLSocket sslSock = (SSLSocket) sSock.accept();
                    // Opening of a Stream for the communication with the client
                    try (ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {

                        // Extraction of the user Public key from the certificate used for the connection
                        byte[] newCom = (byte[]) in.readObject();
                        X509Certificate cert = (X509Certificate) sslSock.getSession().getPeerCertificates()[0];

                        // Adding of the commitment to the database
                        synchronized (commitments) {
                            commitments.put(cert.getPublicKey(), newCom);
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        // Setting the Thread as daemon so it will be closed as soon as the main thread ends the execution
        receiveCommitmentThreadMd.setDaemon(true);
        receiveCommitmentThreadMd.start();
    }

    /**
     * Described in 4.4.3
     * This method generates a Thread that simulates the MD's server that receives a HAToken from the user and its list
     * of contacts. If the token is verified, the contacts are saved into a database.
     */
    private void receiveContactMd() {

        // Defining a thread to simulate the MD server.
        Thread receiveContactThreadMd = new Thread(() -> {
            SSLContext ctx;
            try {
                // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                // Instantiation of the SSLServerSocket
                SSLServerSocketFactory sockFact = ctx.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket) sockFact.createServerSocket(Integer.parseInt(defaultProperties.getProperty("MDTlsSocketReceiveContacts")));
                // This connection doesn't require the client's authentication (One Way Handshake)

                while (true) {
                    // Server's waiting for clients to connect
                    SSLSocket sslSock = (SSLSocket) sSock.accept();

                    // Opening of a Stream for the communication with the client
                    try (ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {
                        // Token reception and verification
                        HAToken token = (HAToken) in.readObject();
                        if (!token.verifyToken()) {
                            System.err.println("Not a valid Token");
                            break;
                        }
                        // If the Token is verified, add contacts to the database
                        ArrayList<ContactMessage> c = (ArrayList<ContactMessage>) in.readObject();
                        addContactToContactList(token, c);
                    }
                }
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | SignatureException | InvalidKeyException | KeyManagementException e) {
                e.printStackTrace();
            }
        });

        // Setting the Thread as daemon so it will be closed as soon as the main thread ends the execution
        receiveContactThreadMd.setDaemon(true);
        receiveContactThreadMd.start();
    }

    /**
     * Described in 4.5.1
     * This method generates a Thread that simulates the MD's server that sends the list of IDs at risk to the client
     */
    private void sendContactListMd() {

        // Defining a thread to simulate the MD server.
        Thread sendContactThreadMd = new Thread(() -> {

            SSLServerSocket sSock;
            SSLContext ctx;
            try {
                // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                // Instantiation of the SSLServerSocket
                SSLServerSocketFactory sockFact = ctx.getServerSocketFactory();
                sSock = (SSLServerSocket) sockFact.createServerSocket(Integer.parseInt(defaultProperties.getProperty("MDTlsSocketSendRiskId")));
                // This SSL connection requires the authentication of the client (Two Way Handshake)
                sSock.setNeedClientAuth(true);

            } catch (Exception e) {
                e.printStackTrace();
                return;
            }

            try {
                while (true) {
                    // Server's waiting for clients to connect
                    SSLSocket sslSock = (SSLSocket) sSock.accept();

                    // Opening of a Stream for the communication with the client
                    try (ObjectOutputStream out = new ObjectOutputStream(sslSock.getOutputStream())) {
                        // Send the list of IDs at risk
                        synchronized (idContactMessage) {
                            out.writeObject(getIds());
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });

        // Setting the Thread as daemon so it will be closed as soon as the main thread ends the execution
        sendContactThreadMd.setDaemon(true);
        sendContactThreadMd.start();
    }

    /**
     * Method that adds the contacts passed as input to the list of contacts at risk that simulates the database if
     * they pass all the verifications described at 2.4 :
     * - verification of the sign of the ID
     * - verification of the match between the Timestamp of the contact and the Date in the HAToken
     */
    private synchronized void addContactToContactList(HAToken token, ArrayList<ContactMessage> contactList) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // Get ID from token
        byte[] idSender = Util.getIdFromPk(token.pkfu);

        // Verification of Contacts as described in 2.4 phase
        ArrayList<DateId> newIdContactMessage = new ArrayList<>();
        for (ContactMessage c : contactList) {
            if (c.verify(idSender) && token.date.equals(c.tsNow.toLocalDate())) {
                newIdContactMessage.add(new DateId(Util.getIdFromPk(c.pkfu1)));
            } else {
                System.out.println("MD : Communication of Fake contacts");
                return;
            }
        }

        // Adding of the contacts
        synchronized (idContactMessage) {
            idContactMessage.addAll(newIdContactMessage);
        }

        System.out.println("MD : Communicated " + contactList.size() + " new contacts");
    }

}
