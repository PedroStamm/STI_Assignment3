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
    private String alias =null;

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

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
