package Kyber;

import Kyber.smartcard.KyberDummySmartCard;

public class SmartCardDummyServer extends Server
{
    private KyberDummySmartCard smartCard;

    protected SmartCardDummyServer(int mode) throws Exception
    {
        super(mode);
        this.smartCard = new KyberDummySmartCard(super.mode, null, false);

        if (super.mode != 512) throw new RuntimeException("Only 512 supported right now");
        this.smartCard.generateKyber512Key();
        System.out.print("[Smart card server] : Public key:  " + this.smartCard.getPublicKey().length + " | "); print(this.smartCard.getPublicKey());
        System.out.print("[Smart card server] : Private key: " + this.smartCard.getPrivateKey().length + " | "); print(this.smartCard.getPrivateKey());
        super.publicKey = this.smartCard.getPublicKey();
    }

    @Override
    public void decapsulate(byte[] encapsulation) throws Exception
    {
        //Only replace when phase 3
        super.aesKey = this.smartCard.decapsulate(super.mode,  encapsulation, this.smartCard.getPrivateKey());
        System.out.print("[Server]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
    }

    @Override
    public byte[] getPublic()
    {
        return super.publicKey;
    }
}