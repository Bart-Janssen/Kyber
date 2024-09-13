package Kyber.Algorithm;

public class KyberDecrypted
{
    private byte[] plainText;
    private byte[] secretKey;

    public KyberDecrypted(byte[] plainText, byte[] secretKey)
    {
        this.plainText = plainText;
        this.secretKey = secretKey;
    }

    public byte[] getPlainText()
    {
        return this.plainText;
    }

    public byte[] getSecretKey()
    {
        return this.secretKey;
    }
}