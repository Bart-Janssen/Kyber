package Kyber.smartcard;

import Kyber.Implementation.SmartCard.Applet;
import Kyber.Models.KyberEncrypted;
import javax.smartcardio.Card;

public class KyberDummySmartCard extends SmartCard
{
    public KyberDummySmartCard(int mode, Card card, boolean showSmartCardLogging)
    {
        super(mode, card, showSmartCardLogging);
    }

    public void generateKyber512Key() throws Exception
    {
        Applet.getInstance().generateKeys(512);
    }

    public byte[] getPublicKey()
    {
        return Applet.getInstance().getPublicKey();
    }

    public byte[] getPrivateKey()
    {
        return Applet.getInstance().getPrivateKey();
    }

    public KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception
    {
        return Applet.getInstance().encapsulate(mode, publicKey);
    }

    public byte[] decapsulate(int mode, byte[] ciphertext, byte[] privateKey) throws Exception
    {
        return Applet.getInstance().decapsulate(mode, privateKey, ciphertext);
    }
}