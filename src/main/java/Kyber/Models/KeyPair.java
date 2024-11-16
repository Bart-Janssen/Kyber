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
            if (paramsK == (short)2)
            {
                keyPair.privateKey = new byte[(short)1632];
                keyPair.publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
            }
            if (paramsK == (short)3)
            {
                keyPair.privateKey = new byte[(short)2400];
                keyPair.publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK768];
            }
            if (paramsK == (short)4)
            {
                keyPair.privateKey = new byte[(short)3168];
                keyPair.publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
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