package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.Util;
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
        byte[] publicKey = new byte[kyber.publicKeyLength];
        Util.arrayCopyNonAtomic(kyber.publicKey, (short)0, publicKey, (short)0, kyber.publicKeyLength);
        return publicKey;
    }

    //Fake apdu call to get private key
    public byte[] getPrivateKey()
    {
        byte[] privateKey = new byte[kyber.privateKeyLength];
        Util.arrayCopyNonAtomic(kyber.privateKey, (short)0, privateKey, (short)0, kyber.privateKeyLength);
        return privateKey;
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
        Util.arrayCopyNonAtomic(publicKey, (short)0, kyber.publicKey, (short)0, kyber.publicKeyLength);
        kyber.encapsulate();
        byte[] encapsulation = new byte[kyber.encapsulationLength];
        Util.arrayCopyNonAtomic(kyber.encapsulation, (short)0, encapsulation, (short)0, kyber.encapsulationLength);
        byte[] secretKey = new byte[32];
        Util.arrayCopyNonAtomic(kyber.secretKey, (short)0, secretKey, (short)0, (short)32);
        return new KyberEncrypted(encapsulation, secretKey);
    }

    @Override
    public byte[] decapsulate(int mode, byte[] privateKey, byte[] encapsulation) throws Exception
    {
        byte paramsK;
        if (mode == 512) paramsK = (byte)2;
        else if (mode == 768) paramsK = (byte)3;
        else if (mode == 1024) paramsK = (byte)4;
        else throw new RuntimeException("Mode not supported");
        kyber = KyberAlgorithm.getInstance(paramsK);
        Util.arrayCopyNonAtomic(privateKey, (short)0, kyber.privateKey, (short)0, kyber.privateKeyLength);
        Util.arrayCopyNonAtomic(encapsulation, (short)0, kyber.encapsulation, (short)0, kyber.encapsulationLength);
        kyber.decapsulate();
        byte[] secretKey = new byte[32];
        Util.arrayCopyNonAtomic(kyber.secretKey, (short)0, secretKey, (short)0, (short)32);
        return secretKey;
    }
}