package Kyber.smartcard;

import Kyber.Implementation.Reference.KyberAlgorithm;
import Kyber.Implementation.SmartCard.Applet;
import Kyber.Models.KyberEncrypted;

import javax.smartcardio.Card;
import java.security.SecureRandom;

public class KyberSmartCard extends SmartCard
{
    private final byte[] kyberApplet512AID = new byte[]{(byte)0x4B,(byte)0x79,(byte)0x62,(byte)0x65,(byte)0x72};

    public KyberSmartCard(int mode, Card card, boolean showSmartCardLogging)
    {
        super(mode, card, showSmartCardLogging);
    }

    public void selectKyberApplet() throws Exception
    {
        super.selectApplet(this.kyberApplet512AID);
    }

    public void generateKyber512Key() throws Exception
    {
        //replace this with actual smart card apdu
        Applet.getInstance().generateKyber512Key();
    }

    public byte[] getPublicKey()
    {
        //replace this with actual smart card apdu
        return Applet.getInstance().getPublicKey();
    }

    public byte[] getPrivateKey()
    {
        //replace this with actual smart card apdu
        return Applet.getInstance().getPrivateKey();
    }

    public KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception
    {
        byte[] random = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(random);
        //I will make random optional random for the algorithm.
        Applet.getInstance().setSharedSecret(random);//optional
        Applet.getInstance().setPublicKey(publicKey, (byte)2);//optional
        if (mode == 512) return Applet.getInstance().encapsulate((byte)2);
//        if (mode == 768) return new KyberAlgorithm().encrypt768(random, publicKey);
//        if (mode == 1024) return new KyberAlgorithm().encrypt1024(random, publicKey);
        throw new RuntimeException("Mode not supported.");
    }
}