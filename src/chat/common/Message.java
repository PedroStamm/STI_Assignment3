package chat.common;

import java.io.Serializable;

/**
 * Created by pedro on 5/28/16.
 */
public class Message implements Serializable {

    //Encrypted message payload
    private String payload=null;

    //Signature for payload
    private byte[] signature=null;

    //User identification
    private String username=null;

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
