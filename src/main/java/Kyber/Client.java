package Kyber;

public abstract class Client
{
    protected byte[] aesKey;
    protected byte[] serverPublic;
    int mode;

    public abstract byte[] encapsulate() throws Exception;

    public String encryptAES(String plainText) throws Exception
    {
        return new AES().encryptAES(plainText, this.aesKey);
    }

    public void setServerPublic(byte[] serverPublicKey)
    {
        this.serverPublic = serverPublicKey;
    }

    protected void print(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : data)
        {
            sb.append(String.format("%02X ", b));
        }
        System.out.print(sb);
        System.out.println();
    }
}