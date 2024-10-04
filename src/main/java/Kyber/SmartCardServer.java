package Kyber;

import Kyber.Implementation.SmartCard.Applet;
import Kyber.service.KyberReferenceService;
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

        if (super.mode != 512) throw new RuntimeException("Only 512 supported right now");
        this.smartCard.generateKyber512Key();
        super.publicKey = this.smartCard.getPublicKey();
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
        //Only replace when phase 3
        super.aesKey = new KyberReferenceService().decapsulate(super.mode, this.smartCard.getPrivateKey(), encapsulation);
        System.out.print("[Server]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
    }

    @Override
    public byte[] getPublic()
    {
        return super.publicKey;
    }
}