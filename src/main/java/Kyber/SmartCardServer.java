package Kyber;

import Kyber.Models.KeyPair;
import Kyber.service.KyberSmartCardService;
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

        KeyPair keyPair = new KyberSmartCardService().generateKeys(super.mode);
        super.privateKey = keyPair.getPrivateKey();
        super.publicKey = keyPair.getPublicKey();
        System.out.print("[Server]  : Public Key length: " + super.publicKey.length + " | ");super.print(super.publicKey);
        System.out.print("[Server]  : Private Key length: " + super.privateKey.length + " | ");super.print(super.privateKey);
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
        super.aesKey = new KyberSmartCardService().decapsulate(super.mode, super.privateKey, encapsulation);
        System.out.print("[Server]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
    }

    @Override
    public byte[] getPublic()
    {
        return super.publicKey;
    }
}