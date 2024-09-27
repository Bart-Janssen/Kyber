package Kyber.smartcard;

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
}