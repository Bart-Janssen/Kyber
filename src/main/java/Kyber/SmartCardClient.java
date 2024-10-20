package Kyber;

import Kyber.Models.KyberEncrypted;
import Kyber.service.KyberReferenceService;
import Kyber.smartcard.KyberSmartCard;

public class SmartCardClient extends Client
{
    private KyberSmartCard smartCard;

    public SmartCardClient(int mode, boolean showSmartCardLogging) throws Exception
    {
        super.mode = mode;
        this.connectSmartCard(showSmartCardLogging);
        if (super.mode != 512) throw new RuntimeException("Only 512 supported right now");
    }

    private void connectSmartCard(boolean showSmartCardLogging)
    {
        try
        {
//            List<CardTerminal> readers = TerminalFactory.getDefault().terminals().list();
//            Card card = readers.get(0).connect("T=1");
            this.smartCard = new KyberSmartCard(super.mode, null, showSmartCardLogging);
            this.smartCard.selectKyberApplet();
        }
        catch (Exception e)
        {
            System.out.println("Not able to receive private key, cannot connect to smart card.");
        }
    }

    @Override
    public byte[] encapsulate() throws Exception
    {
        KyberEncrypted encapsulationWithSecret = this.smartCard.encapsulate(super.mode, super.serverPublic);
        byte[] encapsulation = encapsulationWithSecret.getCipheredText();
        super.aesKey = encapsulationWithSecret.getSecretKey();
        System.out.print("[Smart card client]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
        return encapsulation;
    }
}