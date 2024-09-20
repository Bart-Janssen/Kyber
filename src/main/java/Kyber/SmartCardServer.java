package Kyber;

import Kyber.smartcard.KyberKeyStoreSmartCard;
import Kyber.smartcard.KyberSmartCard;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.util.List;

public class SmartCardServer extends Server
{
    private KyberSmartCard smartCard;

    protected SmartCardServer(int mode, boolean showSmartCardLogging) throws Exception
    {
        super(mode);
        this.connectSmartCard(showSmartCardLogging);
    }

    private void connectSmartCard(boolean showSmartCardLogging)
    {
        try
        {
            List<CardTerminal> readers = TerminalFactory.getDefault().terminals().list();
            Card card = readers.get(0).connect("T=1");
            this.smartCard = new KyberSmartCard(super.mode, card, showSmartCardLogging);
            this.smartCard.selectKyberApplet();
        }
        catch (Exception e)
        {
            System.out.println("Not able to receive private key, cannot connect to smart card.");
        }
    }

    @Override
    public void decapsulate(byte[] encapsulation) throws Exception
    {

    }

    @Override
    public byte[] getPublic()
    {
        return super.publicKey;
    }
}