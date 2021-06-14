package it.unisa.diem.cs.gruppo10;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class MD {
    private final int port;

    private final String passwordKeyStore;
    private final String filepathKeyStore;

    public MD(int port, String filepathKeyStore, String passwordKeyStore) {
        this.port = port;
        // this.userKeyStore = readStore(filepathKeyStore, passwordKeyStore);
        this.passwordKeyStore = passwordKeyStore;
        this.filepathKeyStore = filepathKeyStore;
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
        for (ContactMessage c: contactList){
            if (c.verify(idSender)){
                id_list.add(getId(c.pkfu1));
            } else {
                System.out.println("MD : Communication of Fake contacts");
                return;
            }
        }
        System.out.println("MD : Communicated " + id_list.size() + " new contacts");

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

    // Crea un Thread che pone l'MD in continua attesa di connessioni. Dovranno essere creati un Thread per ogni contatto da comunicare.
    public void connection_MD() {
        Thread startConnectionwithMD = new Thread(() -> {
            SSLServerSocket sSock;

            try {
                // Associazione del KeyStore
                System.setProperty("javax.net.ssl.keyStore", filepathKeyStore);
                System.setProperty("javax.net.ssl.keyStorePassword", passwordKeyStore);

                // Creazione della Socket
                SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                sSock = (SSLServerSocket) sockfact.createServerSocket(port);

            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
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

}
