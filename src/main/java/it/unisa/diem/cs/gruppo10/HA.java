
package it.unisa.diem.cs.gruppo10;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;

public class HA {
    private final Properties haProperties;
    private final Properties defaultProperties;
    private final ArrayList<PublicKey> pkPositive;
    private final SSLSocketFactory factoryClient;
    private final SSLServerSocketFactory factoryServer;
    private KeyPair keyPair;
    private final MD md;

    public HA(MD md) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
        defaultProperties = Util.loadDefaultProperties();
        haProperties = Util.loadProperties("ha.properties");

        pkPositive = new ArrayList<>();
        this.md = md;
        // Read trust store
        TrustManagerFactory tmf = Util.generateTrustStoreManager(Util.resourcesPath + haProperties.getProperty("trustStoreFile"),
                haProperties.getProperty("trustStorePassword"));

        // Read Key Store
        KeyManagerFactory kmf = Util.generateKeyStoreManager(Util.resourcesPath + haProperties.getProperty("keyStoreFile"),
                haProperties.getProperty("keyStorePassword"));

        // Read Certificated KeyPair
        keyPair = Util.readKpFromKeyStore(Util.resourcesPath + haProperties.getProperty("keyStoreFile"),
                haProperties.getProperty("keyStorePassword"), "HA");

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        factoryServer = ctx.getServerSocketFactory();
        factoryClient = ctx.getSocketFactory();

        System.out.println("HA: now I'm ready to provide Token and book swab.");
        getToken(md);
        bookSwabService(md);
    }

    public void setPositive(User u) {
        pkPositive.add(u.getPublicKey());
        System.out.println("HA: " + u.getName() + " is positive to Molecular Swab");
    }

    private void getToken(MD md) {
        Thread tokenRequest = new Thread(() -> {

            // Creazione Socket
            SSLServerSocket sSock;
            try {
                sSock = (SSLServerSocket) factoryServer.createServerSocket(Integer.parseInt(defaultProperties.getProperty("HATlsSReceiveToken")));
                sSock.setNeedClientAuth(true);
                while (true) {
                    try {
                        // Attesa Connessione
                        SSLSocket sslSock = (SSLSocket) sSock.accept();

                        // Connessione con l'utente avvenuta
                        try (ObjectOutputStream out = new ObjectOutputStream(sslSock.getOutputStream());
                             ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {

                            PkfCommitment commUser = (PkfCommitment) in.readObject();
                            X509Certificate cert = (X509Certificate) sslSock.getSession().getPeerCertificates()[0];

                            // Connessione con Server MD
                            byte[] commMD = requestCommitment(md, cert.getPublicKey());

                            // Verification of commitment
                            if (pkPositive.contains(cert.getPublicKey()) &&
                                    PkfCommitment.openCommit(commUser.r, cert.getPublicKey(), commUser.pkf, commUser.date, commMD)) {
                                // Sends a new Token
                                HAToken token = new HAToken(commUser.pkf, commUser.date, keyPair);
                                out.writeObject(token);
                            } else {
                                System.err.println("Commitment non valido");
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
        tokenRequest.setDaemon(true);
        tokenRequest.start();
    }

    private void bookSwabService(MD md) {
        Thread bookSwabThread = new Thread(() -> {
            // Creazione Socket
            SSLServerSocket sSock;
            try {
                sSock = (SSLServerSocket) factoryServer.createServerSocket(Integer.parseInt(defaultProperties.getProperty("HATlsBookSwab")));
                sSock.setNeedClientAuth(true);
                while (true) {
                    try {
                        // Attesa Connessione
                        SSLSocket sslSock = (SSLSocket) sSock.accept();

                        // Connessione con l'utente avvenuta
                        try (ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {

                            PkfCommitment commUser = (PkfCommitment) in.readObject();
                            X509Certificate cert = (X509Certificate) sslSock.getSession().getPeerCertificates()[0];

                            // Connessione con Server MD
                            byte[] commMD = requestCommitment(md, cert.getPublicKey());

                            // Verification of commitment
                            LocalDateTime dtPositivity = md.getDateTimeOfCommunicatedID(Util.getIdFromPk(commUser.pkf));
                            if (PkfCommitment.openCommit(commUser.r, cert.getPublicKey(), commUser.pkf, commUser.date, commMD)
                                    && dtPositivity != null) {
                                if (dtPositivity.plus(1, ChronoUnit.DAYS).isAfter(LocalDateTime.now())) {
                                    System.out.println("HA: booked a swab to " + Util.getIdentityByCertificate(cert).get(1) + " for free");
                                } else {
                                    System.out.println("HA: booked a swab to " + Util.getIdentityByCertificate(cert).get(1) + " for 0.003BTC");
                                }
                            } else {
                                System.err.println("Commitment o data non validi");
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

        bookSwabThread.setDaemon(true);
        bookSwabThread.start();
    }

    private byte[] requestCommitment(MD md, PublicKey pku) throws Exception {
        return md.getCommitments().get(pku);
    }
}