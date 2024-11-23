package Kyber.Implementation.SmartCard;

import Kyber.Models.KeyPair;
import Kyber.Models.KyberEncrypted;
import Kyber.service.KyberService;

//Fake applet
public class Applet extends KyberService
{
    private static Applet applet;

    private KyberAlgorithm kyber;

    public static Applet getInstance()
    {
        if (applet == null) applet = new Applet();
        return applet;
    }

    //Fake apdu call to get public key
    public byte[] getPublicKey()
    {
        return this.kyber.publicKey;
    }

    //Fake apdu call to get private key
    public byte[] getPrivateKey()
    {
        return this.kyber.privateKey;
    }

    @Override
    public KeyPair generateKeys(int mode) throws Exception
    {
        byte paramsK;
        if (mode == 512) paramsK = (byte)2;
        else if (mode == 768) paramsK = (byte)3;
        else if (mode == 1024) paramsK = (byte)4;
        else throw new RuntimeException("Mode not supported");
        kyber = KyberAlgorithm.getInstance(paramsK);
        kyber.generateKeys();
        return new KeyPair(kyber.privateKey, kyber.publicKey);//ignored
    }

    @Override
    public KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception
    {
        byte paramsK;
        if (mode == 512) paramsK = (byte)2;
        else if (mode == 768) paramsK = (byte)3;
        else if (mode == 1024) paramsK = (byte)4;
        else throw new RuntimeException("Mode not supported");
        kyber = KyberAlgorithm.getInstance(paramsK);
        kyber.publicKey = publicKey;
        kyber.encapsulate();
        return new KyberEncrypted(KyberAlgorithm.getInstance(paramsK).encapsulation, KyberAlgorithm.getInstance(paramsK).secretKey);
    }

    @Override
    public byte[] decapsulate(int mode, byte[] privateKey, byte[] encapsulation) throws Exception
    {
        byte paramsK;
        if (mode == 512) paramsK = (byte)2;
        else if (mode == 768) paramsK = (byte)3;
        else if (mode == 1024) paramsK = (byte)4;
        else throw new RuntimeException("Mode not supported");
        kyber.privateKey = privateKey;
        KyberAlgorithm.getInstance(paramsK).encapsulation = encapsulation;
        KyberAlgorithm.getInstance(paramsK).decapsulate();
        return KyberAlgorithm.getInstance(paramsK).secretKey;
    }
}