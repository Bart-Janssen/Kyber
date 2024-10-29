package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Models.KeyPair;
import Kyber.Models.KyberEncrypted;
import Kyber.Models.KyberParams;
import Kyber.service.KyberService;

//Fake applet
public class Applet extends KyberService
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

    @Override
    public KeyPair generateKeys(int mode) throws Exception
    {
        if (mode == 512)
        {
            byte paramsK = (byte)2;
            KyberAlgorithm.getInstance(paramsK).generateKeys(KyberParams.Kyber512SKBytes);
            this.keyPair = KeyPair.getInstance(paramsK);
            return this.keyPair;//ignored
        }
        throw new RuntimeException("Mode not supported");
    }

    @Override
    public KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception
    {
        if (mode == 512)
        {
            byte paramsK = (byte)2;
            this.keyPair = KeyPair.getInstance(paramsK);
            this.keyPair.publicKey = publicKey;//through APDU
            KyberAlgorithm.getInstance(paramsK).encapsulate();
            return new KyberEncrypted(KyberAlgorithm.getInstance(paramsK).encapsulation, KyberAlgorithm.getInstance(paramsK).secretKey);
        }
        throw new RuntimeException("Mode not supported");
    }

    @Override
    public byte[] decapsulate(int mode, byte[] privateKey, byte[] encapsulation) throws Exception
    {
        if (mode == 512)
        {
            byte paramsK = (byte)2;
            this.keyPair = KeyPair.getInstance(paramsK);
            this.keyPair.privateKey = privateKey;//through APDU
            KyberAlgorithm.getInstance(paramsK).encapsulation = encapsulation;
            KyberAlgorithm.getInstance(paramsK).decapsulate(KyberParams.paramsIndcpaSecretKeyBytesK512, KyberParams.paramsIndcpaPublicKeyBytesK512, KyberParams.Kyber512SKBytes);
            return KyberAlgorithm.getInstance(paramsK).secretKey;
        }
        throw new RuntimeException("Mode not supported");
    }
}