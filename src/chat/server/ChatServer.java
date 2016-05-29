package chat.server;


import chat.common.KeyChain;
import chat.common.Message;
import chat.common.MyHandshakeCompletedListener;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.CertificateException;


public class ChatServer implements Runnable {
    private ChatServerThread clients[] = new ChatServerThread[20];
    private SSLServerSocket server_socket = null;
    private Thread thread = null;
    private KeyChain keyChain = null;
    private int clientCount = 0;
    private int msgCount = 0;

    public ChatServer(int port) {
        try {
            // Binds to port and starts server
            System.out.println("Binding to port " + port);

            //Instantiate KeyChain
            keyChain = new KeyChain("/home/pedro/keystores/serverkeystore.jck", "server_password", "/home/pedro/keystores/servertruststore.jck", "server_password");

            //Load Server's keys
            KeyManagerFactory serverKeyManager = KeyManagerFactory.getInstance("SunX509");
            serverKeyManager.init(keyChain.getKeyStore(), keyChain.getKeyStorePass().toCharArray());

            //Load Server-trusted Client keys
            TrustManagerFactory trustManager = TrustManagerFactory.getInstance("SunX509");
            trustManager.init(keyChain.getTrustStore());

            //Create SSL Socket
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(serverKeyManager.getKeyManagers(), trustManager.getTrustManagers(), SecureRandom.getInstance("SHA1PRNG"));
            server_socket = (SSLServerSocket)ssl.getServerSocketFactory().createServerSocket(port);
            server_socket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA"});
            server_socket.setNeedClientAuth(true);
            System.out.println("Server started: " + server_socket);
            start();
        } catch (IOException ioexception) {
            // Error binding to port
            System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
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
                // Adds new thread for new client
                System.out.println("Waiting for a client ...");
                addThread((SSLSocket) server_socket.accept());
            } catch (IOException ioexception) {
                System.out.println("Accept error: " + ioexception);
                stop();
            }
        }
    }

    public void start() {
        if (thread == null) {
            // Starts new thread for client
            thread = new Thread(this);
            thread.start();
        }
    }

    public void stop() {
        if (thread != null) {
            // Stops running thread for client
            thread.stop();
            thread = null;
        }
    }

    private int findClient(int ID) {
        // Returns client from id
        for (int i = 0; i < clientCount; i++)
            if (clients[i].getID() == ID)
                return i;
        return -1;
    }

    public synchronized void handle(int ID, Message input) {
        try {
            if(keyChain.verifySignature("STI3_Client", input.getPayload(), input.getSignature())) {
                if (input.getPayload().equals(".quit")) {
                    int leaving_id = findClient(ID);
                    // Client exits
                    Message msg = new Message();
                    msg.setPayload(".quit");
                    msg.setSignature(keyChain.signData("STI3_Server", msg.getPayload()));
                    clients[leaving_id].send(msg);
                    // Notify remaing users
                    Message msg2 = new Message();
                    msg2.setPayload("Client " + ID + "exits...");
                    msg2.setSignature(keyChain.signData("STI3_Server", msg2.getPayload()));
                    for (int i = 0; i < clientCount; i++)
                        if (i != leaving_id) {
                            clients[i].send(msg2);
                        }
                    remove(ID);
                } else {
                    // Broadcast message for every other client online
                    Message msg = new Message();
                    msg.setPayload(ID + ": " + input.getPayload());
                    msg.setSignature(keyChain.signData("STI3_Server", msg.getPayload()));

                    for (int i = 0; i < clientCount; i++) {
                        clients[i].send(msg);
                    }
                    this.msgCount++;
                    //Renew all Symmetric keys after 10 messages with new handshake
                    if (this.msgCount >= 10) {
                        this.msgCount = 0;
                        for (int i = 0; i < clientCount; i++) {
                            try {
                                clients[i].renegotiate();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            } else {
                System.out.println("Signature does not match message.");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | UnrecoverableKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }

    public synchronized void remove(int ID) {
        int pos = findClient(ID);

        if (pos >= 0) {
            // Removes thread for exiting client
            ChatServerThread toTerminate = clients[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount - 1)
                for (int i = pos + 1; i < clientCount; i++)
                    clients[i - 1] = clients[i];
            clientCount--;

            try {
                toTerminate.close();
            } catch (IOException ioe) {
                System.out.println("Error closing thread: " + ioe);
            }

            toTerminate.stop();
        }
    }

    private void addThread(SSLSocket socket) {
        if (clientCount < clients.length) {
            // Adds thread for new accepted client
            clients[clientCount] = new ChatServerThread(this, socket);
            socket.addHandshakeCompletedListener(new MyHandshakeCompletedListener());

            try {
                clients[clientCount].open();
                clients[clientCount].start();
                clientCount++;
            } catch (IOException ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }


    public static void main(String args[]) {
        ChatServer server = null;

        if (args.length != 1)
            // Displays correct usage for server
            System.out.println("Usage: java ChatServer port");
        else
            // Calls new server
            server = new ChatServer(Integer.parseInt(args[0]));
    }

}

class ChatServerThread extends Thread {
    private ChatServer server = null;
    private SSLSocket socket = null;
    private int ID = -1;
    private ObjectInputStream streamIn = null;
    private ObjectOutputStream streamOut = null;


    public ChatServerThread(ChatServer _server, SSLSocket _socket) {
        super();
        server = _server;
        socket = _socket;
        ID = socket.getPort();
    }

    // Sends message to client
    public void send(Message msg) {
        try {
            streamOut.writeObject(msg);
            streamOut.flush();
        } catch (IOException ioexception) {
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            stop();
        }
    }

    // Gets id for client
    public int getID() {
        return ID;
    }

    // Runs thread
    public void run() {
        System.out.println("Server Thread " + ID + " running.");

        while (true) {
            try {
                server.handle(ID, (Message)streamIn.readObject());
            } catch (IOException ioe) {
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                stop();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }


    // Opens thread
    public void open() throws IOException {
        streamIn = new ObjectInputStream(socket.getInputStream());
        streamOut = new ObjectOutputStream(socket.getOutputStream());
    }

    // Closes thread
    public void close() throws IOException {
        if (socket != null) socket.close();
        if (streamIn != null) streamIn.close();
        if (streamOut != null) streamOut.close();
    }

    public void renegotiate() throws IOException {
        socket.startHandshake();
    }

}

