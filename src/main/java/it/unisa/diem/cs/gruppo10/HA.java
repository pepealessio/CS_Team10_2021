package it.unisa.diem.cs.gruppo10;

import javax.net.ssl.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Properties;

/**
 * Ths class is used to simulate an user in the CT system.
 */
public class HA {
    private final Properties defaultProperties;
    private final ArrayList<PublicKey> pkPositive;
    private final KeyPair keyPair;
    private final TrustManagerFactory tmf;
    private final KeyManagerFactory kmf;

    public HA(MD md) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        defaultProperties = Util.loadDefaultProperties();
        Properties haProperties = Util.loadProperties("ha.properties");

        pkPositive = new ArrayList<>();
        // Read trust store
        tmf = Util.generateTrustStoreManager(Util.resourcesPath + haProperties.getProperty("trustStoreFile"),
                haProperties.getProperty("trustStorePassword"));

        // Read Key Store
        kmf = Util.generateKeyStoreManager(Util.resourcesPath + haProperties.getProperty("keyStoreFile"),
                haProperties.getProperty("keyStorePassword"));

        // Read Certificated KeyPair
        keyPair = Util.readKpFromKeyStore(Util.resourcesPath + haProperties.getProperty("keyStoreFile"),
                haProperties.getProperty("keyStorePassword"), "HA");


        System.out.println("HA: now I'm ready to provide Token and book swab.");
        getToken(md);
        bookSwabService(md);
    }

    /**
     * Method to simulate the positive result of a user to a molecular swab. The user is added to the database of
     * positive people.
     *
     * @param u - the user that resulted positive
     */
    public void setPositive(User u) {
        pkPositive.add(u.getPublicKey());
        System.out.println("HA: " + u.getName() + " is positive to the Molecular Swab");
    }

    /**
     * Described in 4.4.2
     * This method generates a Thread that simulates the HA's server that receives a PkfCommitment, requests the
     * commitment related to the public key of the user (extracted from the certificate of the connection) and, if the
     * verifications pass, sends back an HAToken to the user.
     *
     * @param md - an MD instance
     */
    private void getToken(MD md) {
        Thread tokenRequest = new Thread(() -> {

            SSLServerSocket sSock;
            SSLContext ctx;
            try {
                // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                // Instantiation of the SSLServerSocket
                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                sSock = (SSLServerSocket) factory.createServerSocket(Integer.parseInt(defaultProperties.getProperty("HATlsSReceiveToken")));
                // This SSL connection requires the authentication of the client (Two Way Handshake)
                sSock.setNeedClientAuth(true);
                while (true) {
                    try {
                        // Server's waiting for clients to connect
                        SSLSocket sslSock = (SSLSocket) sSock.accept();

                        // Opening of a Stream for the communication with the client
                        try (ObjectOutputStream out = new ObjectOutputStream(sslSock.getOutputStream());
                             ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {

                            // Extract the certificate that the client used to be authenticated in order to extract its
                            // public key
                            PkfCommitment commUser = (PkfCommitment) in.readObject();
                            X509Certificate cert = (X509Certificate) sslSock.getSession().getPeerCertificates()[0];

                            // Simulation of the connection to the MD to get the commitment
                            byte[] commMD = requestCommitment(md, cert.getPublicKey());
                            // commMD[4] = 0xF;

                            // Verification of commitment
                            if (pkPositive.contains(cert.getPublicKey()) &&
                                    PkfCommitment.openCommit(commUser.r, cert.getPublicKey(), commUser.pkf, commUser.date, commMD)) {
                                // Sends a new Token
                                HAToken token = new HAToken(commUser.pkf, commUser.date, keyPair);
                                out.writeObject(token);
                            } else {
                                System.err.println("Not a Valid Commitment");
                                out.writeObject(null);
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        // Setting the Thread as daemon so it will be closed as soon as the main thread ends the execution
        tokenRequest.setDaemon(true);
        tokenRequest.start();
    }

    /**
     * Described in 4.5.2
     * This method generates a Thread that simulates the HA's server that receives a PkfCommitment, requests the
     * commitment related to the public key of the user (extracted from the certificate of the connection) and, if the
     * verifications pass, performs and additional comparison on the time of the request and the time of recorded
     * positivity. If it took place less than 24h after, the swab will be free otherwise the user will be charged.
     *
     * @param md - the MD to connect with
     */
    private void bookSwabService(MD md) {
        Thread bookSwabThread = new Thread(() -> {

            SSLServerSocket sSock;
            SSLContext ctx;
            try {
                // SSLContext creation with KeyStore Managers, TrustStore Managers and a source of randomness
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                // Instantiation of the SSLServerSocket
                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                sSock = (SSLServerSocket) factory.createServerSocket(Integer.parseInt(defaultProperties.getProperty("HATlsBookSwab")));
                // This SSL connection requires the authentication of the client (Two Way Handshake)
                sSock.setNeedClientAuth(true);
                while (true) {
                    try {
                        // Server's waiting for clients to connect
                        SSLSocket sslSock = (SSLSocket) sSock.accept();

                        // Opening of a Stream for the communication with the client
                        try (ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {

                            // Extract the certificate that the client used to be authenticated in order to extract its
                            // public key
                            PkfCommitment commUser = (PkfCommitment) in.readObject();
                            X509Certificate cert = (X509Certificate) sslSock.getSession().getPeerCertificates()[0];

                            // Simulation of the connection to the MD to get the commitment
                            byte[] commMD = requestCommitment(md, cert.getPublicKey());

                            // Verification of commitment
                            LocalDateTime dtPositivity = md.getDateTimeOfCommunicatedID(Util.getIdFromPk(commUser.pkf));
                            if (PkfCommitment.openCommit(commUser.r, cert.getPublicKey(), commUser.pkf, commUser.date, commMD)
                                    && dtPositivity != null) {

                                // Comparison between the dates
                                if (dtPositivity.plus(1, ChronoUnit.DAYS).isAfter(LocalDateTime.now())) {
                                    System.out.println("HA: booked a swab to " + Util.getIdentityByCertificate(cert).get(2) + " for free");
                                } else {
                                    System.out.println("HA: booked a swab to " + Util.getIdentityByCertificate(cert).get(2) + " for 0.001BTC");
                                }
                            } else {
                                System.err.println("Not valid commitment or data");
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        // Setting the Thread as daemon so it will be closed as soon as the main thread ends the execution
        bookSwabThread.setDaemon(true);
        bookSwabThread.start();
    }

    /**
     * This method simulates the HA's access to the commitments' database.
     *
     *
     * @param md  - the MD to connect with
     * @param pku - the public key of the user whom commitment is requested
     * @return the commitment related to the public key
     */
    private byte[] requestCommitment(MD md, PublicKey pku) {
        return md.getCommitments().get(pku);
    }
}