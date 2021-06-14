package it.unisa.diem.cs.gruppo10;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class MD {
    private final int port;
    private final int port2;
    private final String passwordKeyStore;
    private final String filepathKeyStore;
    private final String passwordTrustStore;
    private final String filepathTrustStore;

    public MD(int port, int port2, String filepathKeyStore, String passwordKeyStore, String filepathTrustStore,
              String passwordTrustStore) {
        this.port = port;
        this.port2 = port2;
        // this.userKeyStore = readStore(filepathKeyStore, passwordKeyStore);
        this.passwordKeyStore = passwordKeyStore;
        this.filepathKeyStore = filepathKeyStore;
        this.passwordTrustStore = passwordTrustStore;
        this.filepathTrustStore = filepathTrustStore;
    }

    // In caso si debba caricare l'intero keystore
    private KeyStore readStore(String filepath, String password) {
        try {

            InputStream stream = new FileInputStream(filepath);
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] trustStorePassword = password.toCharArray();
            store.load(stream, trustStorePassword);

           /* //This is defining the SSLContext so the trust store will be used
            //Getting default SSLContext to edit.
            SSLContext context = SSLContext.getInstance("SSL");
            //TrustMangers hold trust stores, more than one can be added
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            //Adds the truststore to the factory
            factory.init(store);
            //This is passed to the SSLContext init method
            TrustManager[] managers = factory.getTrustManagers();
            context.init(null, managers, null);
            //Sets our new SSLContext to be used.
            SSLContext.setDefault(context);*/

            return store;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            //Handle error
            ex.printStackTrace();
            return null;
        }

    }

    private void addContactToContactList(PublicKey pk, ArrayList<ContactMessage> contactList) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        ArrayList<byte[]> id_list;
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream("contact_list.server"))) {
            id_list = (ArrayList<byte[]>) in.readObject();
        } catch (Exception e) {
            id_list = new ArrayList<>();
        }

        byte[] idSender = getId(pk);
        for (ContactMessage c : contactList) {
            if (c.verify(idSender)) {
                id_list.add(getId(c.pkfu1));
            } else {
                System.out.println("MD : Communication of Fake contacts");
                return;
            }
        }
        System.out.println("MD : Communicated " + contactList.size() + " new contacts");

        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("contact_list.server"))) {
            out.writeObject(id_list);
        } catch (Exception ignored) {

        }

    }

    private byte[] getId(PublicKey pk) throws NoSuchAlgorithmException {
        byte[] pkByte = pk.getEncoded();
        MessageDigest h = MessageDigest.getInstance("SHA256");
        h.update(pkByte);
        return Arrays.copyOfRange(h.digest(), 0, 16);
    }

    public int getPort() {
        return port;
    }

    public int getPort2() {
        return port2;
    }

    // Crea un Thread che pone l'MD in continua attesa di connessioni. Dovranno essere creati un Thread per ogni contatto da comunicare.
    public void receiveContactMd() {
        Thread startConnectionwithMD = new Thread(() -> {
            SSLServerSocket sSock;

            try {
                // Associazione del KeyStore
                System.setProperty("javax.net.ssl.keyStore", filepathKeyStore);
                System.setProperty("javax.net.ssl.keyStorePassword", passwordKeyStore);
                System.setProperty("javax.net.ssl.trustStore", filepathTrustStore);
                System.setProperty("javax.net.ssl.trustStorePassword", passwordTrustStore);


                // Creazione della Socket
                SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                sSock = (SSLServerSocket) sockfact.createServerSocket(port);

            } catch (Exception e) {
                e.printStackTrace();
                return;
            }

            System.out.println("MD server is now on");

            while (true) {

                try {
                    // Attesa Connessione
                    SSLSocket sslSock = (SSLSocket) sSock.accept();

                    ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream());
                    // Se avviene la connessione, si prosegue con il caricamento del contatto ricevuto
                    PublicKey pkfu1 = (PublicKey) in.readObject();
                    ArrayList<ContactMessage> c = (ArrayList<ContactMessage>) in.readObject();
                    addContactToContactList(pkfu1, c);
                    in.close();

                } catch (Exception e) {
                    e.printStackTrace();
                    System.err.println("SERVER : " + e);
                }
            }
        });

        startConnectionwithMD.start();
    }

    public void sendContactListMd() {
        Thread startConnectionwithMD = new Thread(() -> {
            SSLServerSocket sSock;

            try {
                // Associazione del KeyStore
                System.setProperty("javax.net.ssl.keyStore", filepathKeyStore);
                System.setProperty("javax.net.ssl.keyStorePassword", passwordKeyStore);

                System.setProperty("javax.net.ssl.trustStore", filepathTrustStore);
                System.setProperty("javax.net.ssl.trustStorePassword", passwordTrustStore);

                // Creazione della Socket
                SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                sSock = (SSLServerSocket) sockfact.createServerSocket(port2);
                sSock.setNeedClientAuth(true);

            } catch (Exception e) {
                e.printStackTrace();
                return;
            }

            while (true) {

                try {
                    // Attesa Connessione
                    SSLSocket sslSock = (SSLSocket) sSock.accept();

                    //
                    ArrayList<byte[]> id_list;
                    try (ObjectInputStream in = new ObjectInputStream(new FileInputStream("contact_list.server"))) {
                        id_list = (ArrayList<byte[]>) in.readObject();
                    } catch (Exception e) {
                        id_list = new ArrayList<>();
                    }

                    ObjectOutputStream out = new ObjectOutputStream(sslSock.getOutputStream());
                    out.writeObject(id_list);
                    out.close();

                } catch (Exception e) {
                    e.printStackTrace();
                    System.err.println("SERVER : " + e);
                }
            }
        });

        startConnectionwithMD.start();

    }


}
