package Kyber;
public abstract class Client
{
    protected byte[] aesKey;
    protected byte[] serverPublic;

    public abstract byte[] encapsulate() throws Exception;
    public abstract String encryptAES(String plainText) throws Exception;

    public void setServerPublic(byte[] serverPublicKey)
    {
        this.serverPublic = serverPublicKey;
    }
}