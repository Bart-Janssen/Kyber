package Kyber.Implementation.SmartCard;

import Kyber.Models.KeyPair;
import Kyber.Models.KyberParams;

//Fake applet
public class Applet
{
    private static Applet applet;

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
        KyberAlgorithm.getInstance().generateKeys(paramsK, KyberParams.Kyber512SKBytes);
        this.keyPair = KeyPair.getInstance(paramsK);
    }

    //Fake apdu call to get public key
    public byte[] getPublicKey()
    {
        return this.keyPair.getPublicKey();
    }

    //Fake apdu call to get private key (for as long this is not yet implemented in the smart card, will be removed at phase 3)
    public byte[] getPrivateKey()
    {
        return this.keyPair.getPrivateKey();
    }
}