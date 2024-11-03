package Kyber;

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
        this.smartCard.selectKyberApplet();

        if (super.mode != 512) throw new RuntimeException("Only 512 supported right now");
        this.smartCard.generateKyber512Key();
        System.out.println("Public/Private key pair is generated.");
//        System.out.print("[Smart card server] : Public key:  " + super.publicKey.length + " | "); print(super.publicKey);
//        System.out.print("[Smart card server] : Private key: " + this.smartCard.getPrivateKey().length + " | "); print(this.smartCard.getPrivateKey());
    }

    private void connectSmartCard(boolean showSmartCardLogging)
    {
        try
        {
            List<CardTerminal> readers = TerminalFactory.getDefault().terminals().list();
            Card card = readers.get(0).connect("T=1");
            this.smartCard = new KyberSmartCard(super.mode, card, showSmartCardLogging);
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
        super.aesKey = this.smartCard.decapsulate(super.mode,  encapsulation);
        System.out.print("[Server]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
    }

    @Override
    public byte[] getPublic() throws Exception
    {
        return this.smartCard.getPublicKey();
    }
}