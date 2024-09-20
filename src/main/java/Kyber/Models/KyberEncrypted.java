package Kyber.Models;

public class KyberEncrypted
{
    private byte[] cipheredText;
    private byte[] secretKey;

    public KyberEncrypted(byte[] cipheredText, byte[] secretKey)
    {
        this.cipheredText = cipheredText;
        this.secretKey = secretKey;
    }

    public byte[] getCipheredText()
    {
        return this.cipheredText;
    }

    public byte[] getSecretKey()
    {
        return this.secretKey;
    }
}