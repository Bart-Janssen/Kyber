package Kyber.smartcard;

import javax.smartcardio.Card;

public class KyberSmartCard extends SmartCard
{
    private final byte[] kyberAppletAID = new byte[]{(byte)0x50,(byte)0x51,(byte)0x43,(byte)0x20,(byte)0x4B,(byte)0x65,(byte)0x79,(byte)0x73,(byte)0x74,(byte)0x6F,(byte)0x72,(byte)0x65};

    public KyberSmartCard(int mode, Card card, boolean showSmartCardLogging)
    {
        super(mode, card, showSmartCardLogging);
    }

    public void selectKyberApplet() throws Exception
    {
        super.selectApplet(this.kyberAppletAID);
    }
}