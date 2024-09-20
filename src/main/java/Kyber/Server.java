package Kyber;

public abstract class Server
{
    protected byte[] privateKey;
    protected byte[] publicKey;
    protected byte[] aesKey;
    protected int mode;

    protected Server(int mode)
    {
        this.mode = mode;
    }

    public abstract byte[] getPublic();
    public abstract void decapsulate(byte[] encapsulation) throws Exception;

    public String decryptAES(String encryptedText) throws Exception
    {
        return new AES().decryptAES(encryptedText, this.aesKey);
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