package Kyber;

import Kyber.Models.KyberEncrypted;
import Kyber.smartcard.KyberDummySmartCard;

public class SmartCardDummyClient extends Client
{
    private KyberDummySmartCard smartCard;

    public SmartCardDummyClient(int mode) throws Exception
    {
        super.mode = mode;
        this.smartCard = new KyberDummySmartCard(super.mode, null, false);
        if (super.mode != 512) throw new RuntimeException("Only 512 supported right now");
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