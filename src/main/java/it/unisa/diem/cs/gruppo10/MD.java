package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.util.*;

public class MD {
    private final Properties mdProperties;
    private final ArrayList<byte[]> idContactMessage;

    public MD() {
        mdProperties = Util.loadProperties("md.properties");
        idContactMessage = new ArrayList<>();

        System.setProperty("javax.net.ssl.keyStore", Util.resourcesPath + mdProperties.getProperty("keyStoreFile"));
        System.setProperty("javax.net.ssl.keyStorePassword", mdProperties.getProperty("keyStorePassword"));
        System.setProperty("javax.net.ssl.trustStore", Util.resourcesPath + mdProperties.getProperty("trustStoreFile"));
        System.setProperty("javax.net.ssl.trustStorePassword", mdProperties.getProperty("trustStorePassword"));

        receiveContactMd();
        sendContactListMd();

        System.out.println("MD: Now I'm ready to receive authenticated contact and to send ID list. ");
    }

    // Crea un Thread che pone l'MD in continua attesa di connessioni. Dovranno essere creati un Thread per ogni contatto da comunicare.
    private void receiveContactMd() {

        // Defining a thread to simulate the MD server.
        Thread receiveContactThreadMd = new Thread(() -> {
            SSLServerSocket sSock;

            // Creazione della Socket
            SSLServerSocketFactory sockFact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try {
                sSock = (SSLServerSocket) sockFact.createServerSocket(Integer.parseInt(mdProperties.getProperty("TlsSocketReceiveContacts")));

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
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
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

            try {
                SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                sSock = (SSLServerSocket) sockfact.createServerSocket(Integer.parseInt(mdProperties.getProperty("TlsSocketSendRiskId")));
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
