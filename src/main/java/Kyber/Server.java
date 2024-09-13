package Kyber;

public abstract class Server
{
    protected byte[] privateKey;
    protected byte[] publicKey;
    protected byte[] aesKey;

    public abstract byte[] getPublic();
    public abstract void decapsulate(byte[] encapsulation) throws Exception;
    public abstract String decryptAES(String encryptedText) throws Exception;
}