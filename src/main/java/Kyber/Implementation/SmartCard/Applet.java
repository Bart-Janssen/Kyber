package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Models.KeyPair;
import Kyber.Models.KyberEncrypted;
import Kyber.Models.KyberParams;

//Fake applet
public class Applet
{
    private static Applet applet;
    private byte[] sharedSecred = new byte[32];

    //Fake keypair in smart card
    private KeyPair keyPair;

    public static Applet getInstance()
    {
        if (applet == null) applet = new Applet();
        return applet;
    }

    //Fake apdu call to generate 512 keys
    public void generateKyber512Key() throws Exception
    {
        byte paramsK = (byte)2;
        KyberAlgorithm.getInstance(paramsK).generateKeys(KyberParams.Kyber512SKBytes);
        this.keyPair = KeyPair.getInstance(paramsK);
    }

    //Fake apdu call to get public key
    public byte[] getPublicKey()
    {
        return this.keyPair.publicKey;
    }

    //Fake apdu call to get private key (for as long this is not yet implemented in the smart card, will be removed at phase 3)
    public byte[] getPrivateKey()
    {
        return this.keyPair.privateKey;
    }

    public KyberEncrypted encapsulate(byte paramsK) throws Exception
    {
        KyberAlgorithm.getInstance(paramsK).encapsulate();
        return new KyberEncrypted(KyberAlgorithm.getInstance(paramsK).cipheredText, KyberAlgorithm.getInstance(paramsK).secretKey);
    }

    public void setPublicKey(byte[] publicKey, byte paramsK)
    {
        this.keyPair = KeyPair.getInstance(paramsK);
        this.keyPair.publicKey = publicKey;//through APDU
    }
}