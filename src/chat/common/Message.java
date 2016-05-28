package chat.common;

/**
 * Created by pedro on 5/28/16.
 */
public class Message {

    //Encrypted message payload
    private String payload=null;

    //Signature for payload
    private String signature=null;

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
