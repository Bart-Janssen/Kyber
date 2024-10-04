package Kyber.smartcard;

import Kyber.Implementation.SmartCard.Applet;

import javax.smartcardio.Card;

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
}