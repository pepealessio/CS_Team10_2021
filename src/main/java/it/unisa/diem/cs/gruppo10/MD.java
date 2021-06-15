package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

public class MD {
    private final Properties mdProperties;
    private final Properties defaultProperties;
    private final ArrayList<byte[]> idContactMessage;
    private final TrustManagerFactory tmf;
     final HashMap<byte[], byte[]> commitments;
    private final KeyManagerFactory kmf;

    public MD() throws Exception {
        mdProperties = Util.loadProperties("md.properties");
        defaultProperties = Util.loadDefaultProperties();

        idContactMessage = new ArrayList<>();
        this.commitments = new HashMap<>();

        // Read trust store
        tmf = Util.generateTrustStoreManager(Util.resourcesPath + mdProperties.getProperty("trustStoreFile"),
                mdProperties.getProperty("trustStorePassword"));

        // Read Key Store
        kmf = Util.generateKeyStoreManager(Util.resourcesPath + mdProperties.getProperty("keyStoreFile"),
                mdProperties.getProperty("keyStorePassword"));

        receiveCommitmentMd();
        receiveContactMd();
        sendContactListMd();


        System.out.println("MD: Now I'm ready to receive authenticated contact and to send ID list. ");
    }

    private void receiveCommitmentMd() throws Exception {
        // Defining a thread to simulate the MD server.
        Thread receiveCommitmentThreadMd = new Thread(() -> {
            // Creazione della Socket
            SSLContext ctx = null;
            try {
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket) factory.createServerSocket(Integer.parseInt(defaultProperties.getProperty("MDTlsSocketReceiveCommitment")));
                sSock.setNeedClientAuth(true);
                while (true) {
                    // Attesa Connessione
                    SSLSocket sslSock = (SSLSocket) sSock.accept();

                    try (ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {
                        byte[] newCom = (byte[]) in.readObject();
                        X509Certificate cert = (X509Certificate) sslSock.getSession().getPeerCertificates()[0];
                        synchronized (commitments) {
                            commitments.put(cert.getPublicKey().getEncoded(), newCom);
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        receiveCommitmentThreadMd.setDaemon(true);
        receiveCommitmentThreadMd.start();
    }

    // Crea un Thread che pone l'MD in continua attesa di connessioni. Dovranno essere creati un Thread per ogni contatto da comunicare.
    private void receiveContactMd() {

        // Defining a thread to simulate the MD server.
        Thread receiveContactThreadMd = new Thread(() -> {
            // Creazione della Socket
            SSLContext ctx = null;
            try {
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                SSLServerSocketFactory sockFact = ctx.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket) sockFact.createServerSocket(Integer.parseInt(mdProperties.getProperty("TlsSocketReceiveContacts")));

                while (true) {
                    // Attesa Connessione
                    SSLSocket sslSock = (SSLSocket) sSock.accept();

                    // Se avviene la connessione, si prosegue con il caricamento del contatto ricevuto
                    try (ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream())) {
                        PublicKey pkfu1 = (PublicKey) in.readObject();
                        ArrayList<ContactMessage> c = (ArrayList<ContactMessage>) in.readObject();
                        addContactToContactList(pkfu1, c);
                    }
                }
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | SignatureException | InvalidKeyException | KeyManagementException e) {
                e.printStackTrace();
            }
        });

        receiveContactThreadMd.setDaemon(true);
        receiveContactThreadMd.start();
    }

    private void sendContactListMd() {

        // Defining a thread to simulate the MD server.
        Thread sendContactThreadMd = new Thread(() -> {
            Security.addProvider(new BouncyCastleProvider());

            SSLServerSocket sSock;
            SSLContext ctx = null;
            try {
                ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                SSLServerSocketFactory sockFact = ctx.getServerSocketFactory();
                sSock = (SSLServerSocket) sockFact.createServerSocket(Integer.parseInt(mdProperties.getProperty("TlsSocketSendRiskId")));
                sSock.setNeedClientAuth(true);

            } catch (Exception e) {
                e.printStackTrace();
                return;
            }

            try {
                while (true) {
                    // Attesa Connessione
                    SSLSocket sslSock = (SSLSocket) sSock.accept();

                    try (ObjectOutputStream out = new ObjectOutputStream(sslSock.getOutputStream())) {
                        synchronized (idContactMessage) {
                            out.writeObject(idContactMessage);
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }

        });

        sendContactThreadMd.setDaemon(true);
        sendContactThreadMd.start();
    }

    private synchronized void addContactToContactList(PublicKey pk, ArrayList<ContactMessage> contactList) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // Get ID from token
        byte[] idSender = Util.getIdFromPk(pk);

        // Verify Contact as 2.4 phase
        ArrayList<byte[]> newIdContactMessage = new ArrayList<>();
        for (ContactMessage c : contactList) {
            if (c.verify(idSender)) {
                newIdContactMessage.add(Util.getIdFromPk(c.pkfu1));
            } else {
                System.out.println("MD : Communication of Fake contacts");
                return;
            }
        }

        // Add contact
        synchronized (idContactMessage) {
            idContactMessage.addAll(newIdContactMessage);
        }

        System.out.println("MD : Communicated " + contactList.size() + " new contacts");
    }


}
