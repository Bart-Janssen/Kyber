package Kyber.Algorithm;

public class KeyPair
{
    private final byte[] privateKey;
    private final byte[] publicKey;

    public KeyPair(byte[] privateKey, byte[] publicKey)
    {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public byte[] getPrivateKey()
    {
        return this.privateKey;
    }

    public byte[] getPublicKey()
    {
        return this.publicKey;
    }
}