package chat.client;

import chat.common.KeyChain;
import chat.common.Message;
import chat.common.MyHandshakeCompletedListener;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;


public class ChatClient implements Runnable {
    private SSLSocket socket = null;
    private Thread thread = null;
    private DataInputStream console = null;
    private ObjectOutputStream streamOut = null;
    private ChatClientThread client = null;
    private KeyChain keyChain = null;

    public ChatClient(String serverName, int serverPort) {
        System.out.println("Establishing connection to server...");

        try {
            //Instantiate KeyChain
            keyChain = new KeyChain("/home/pedro/keystores/clientkeystore.jck", "client_password", "/home/pedro/keystores/clienttruststore.jck", "client_password");

            //Load Client keys
            KeyManagerFactory clientKeyManager = KeyManagerFactory.getInstance("SunX509");
            clientKeyManager.init(keyChain.getKeyStore(), keyChain.getKeyStorePass().toCharArray());

            //Load Client-trusted Server keys
            TrustManagerFactory trustManager=TrustManagerFactory.getInstance("SunX509");
            trustManager.init(keyChain.getTrustStore());

            //Establish SSLContext security settings
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(clientKeyManager.getKeyManagers(), trustManager.getTrustManagers(), SecureRandom.getInstance("SHA1PRNG"));

            //Get Socket
            socket = (SSLSocket)ssl.getSocketFactory().createSocket(serverName, serverPort);
            socket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"});
            //Add listener for HandshakeCompleted Event
            socket.addHandshakeCompletedListener(new MyHandshakeCompletedListener());
            socket.startHandshake();
            System.out.println("Connected to server: " + socket);
            start();
        } catch (UnknownHostException uhe) {
            // Host unknown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
        } catch (IOException ioexception) {
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        } catch (KeyStoreException e) {
            System.out.println("KeyStore error: "+e.getMessage());
        } catch (CertificateException e) {
            System.out.println("Certificate error: "+e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm error: "+e.getMessage());
        } catch (UnrecoverableKeyException e) {
            System.out.println("Key error: "+e.getMessage());
        } catch (KeyManagementException e) {
            System.out.println("Key Management error: "+e.getMessage());
        }

    }

    public void run() {
        while (thread != null) {
            try {
                // Sends message from console to server
                String str = console.readLine();
                Message msg = new Message();
                msg.setPayload(str);
                msg.setSignature(keyChain.signData("STI3_Client", str));
                streamOut.writeObject(msg);
                streamOut.flush();
            } catch (IOException ioexception) {
                System.out.println("Error sending string to server: " + ioexception.getMessage());
                stop();
            } catch (NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException | KeyStoreException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }


    public void handle(Message msg) {
        // Receives message from server
        try {
            if(keyChain.verifySignature("STI3_Server", msg.getPayload(), msg.getSignature())) {
                if (msg.getPayload().equals(".quit")) {
                    // Leaving, quit command
                    System.out.println("Exiting...Please press RETURN to exit ...");
                    stop();
                } else
                    // else, writes message received from server to console
                    System.out.println(msg.getPayload());
            } else {
                System.out.println("Signature does not match message.");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | SignatureException e) {
            e.printStackTrace();
        }
    }

    // Initiates new client thread
    public void start() throws IOException {
        console = new DataInputStream(System.in);
        streamOut = new ObjectOutputStream(socket.getOutputStream());
        if (thread == null) {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    public void stop() {
        if (thread != null) {
            thread.stop();
            thread = null;
        }
        try {
            if (console != null) console.close();
            if (streamOut != null) streamOut.close();
            if (socket != null) socket.close();
        } catch (IOException ioe) {
            System.out.println("Error closing thread...");
        }
        client.close();
        client.stop();
    }


    public static void main(String args[]) {
        ChatClient client = null;
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]));
    }

}

class ChatClientThread extends Thread {
    private Socket socket = null;
    private ChatClient client = null;
    private ObjectInputStream streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket) {
        client = _client;
        socket = _socket;
        open();
        start();
    }

    public void open() {
        try {
            streamIn = new ObjectInputStream(socket.getInputStream());
        } catch (IOException ioe) {
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    public void close() {
        try {
            if (streamIn != null) streamIn.close();
        } catch (IOException ioe) {
            System.out.println("Error closing input stream: " + ioe);
        }
    }

    public void run() {
        while (true) {
            try {
                client.handle((Message) streamIn.readObject());
            } catch (IOException ioe) {
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
}

