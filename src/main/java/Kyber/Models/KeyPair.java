package Kyber.Models;

public class KeyPair
{
    public byte[] privateKey;
    public byte[] publicKey;

    private static KeyPair keyPair = null;

    private KeyPair(){}

    public static KeyPair getInstance(byte paramsK)
    {
        if (keyPair == null)
        {
            keyPair = new KeyPair();
            //Only kyber 512 for now
            if (paramsK == (short)2)
            {
                keyPair.privateKey = new byte[(short)1632];
                keyPair.publicKey = new byte[(short)800];
            }
        }
        return keyPair;
    }

    public KeyPair(byte[] privateKey, byte[] publicKey)
    {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
}