package it.unisa.diem.cs.gruppo10;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.*;
import java.security.cert.Certificate;
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

    // TODO: Aggiungere contatto alla lista
    private void add_contact_to_contact_list(ArrayList<ContactMessage> newContact) {
        // Scrivi nel file
        System.out.println(newContact);
        System.out.println("Nuovo Contatto aggiunto");
    }

    // Crea un Thread che pone l'MD in continua attesa di connessioni. Dovranno essere creati un Thread per ogni contatto da comunicare.
    public void connection_MD() {
        Thread startConnectionwithMD = new Thread(() -> {
            SSLServerSocket sSock;
            try {
                // Creazione della Socket
                SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                sSock = (SSLServerSocket) sockfact.createServerSocket(port);
                sSock.setEnabledProtocols(sSock.getSupportedProtocols());
                sSock.setEnabledCipherSuites(sSock.getSupportedCipherSuites());
                System.setProperty("javax.net.ssl.keyStore", filepathKeyStore);
                System.setProperty("javax.net.ssl.keyStorePassword", passwordKeyStore);


            } catch (Exception e) {
                System.out.println(e);
                return;
            }
            while (true) {

                try {
                    // Attesa Connessione
                    SSLSocket sslSock = (SSLSocket) sSock.accept();
                    System.out.println("Indirizzo: " + sslSock.getRemoteSocketAddress());
                    ObjectInputStream in = new ObjectInputStream(sslSock.getInputStream());

                    // Se avviene la connessione, si prosegue con il caricamento del contatto ricevuto
                    add_contact_to_contact_list((ArrayList<ContactMessage>) in.readObject());

                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }
        });

        startConnectionwithMD.start();
    }

}
