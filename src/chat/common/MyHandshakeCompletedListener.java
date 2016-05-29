package chat.common;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;

/**
 * Created by pedro on 5/29/16.
 */
public class MyHandshakeCompletedListener implements HandshakeCompletedListener {
    @Override
    public void handshakeCompleted(HandshakeCompletedEvent e) {
        System.out.println("Handshake successful!");
        System.out.println("Using cipher suite: " + e.getCipherSuite()+"\nSession: "+e.getSession());
    }
}
