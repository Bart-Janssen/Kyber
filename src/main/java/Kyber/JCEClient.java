package Kyber;

import Kyber.Models.KyberEncrypted;

public class JCEClient extends Client
{
    public JCEClient(int mode)
    {
        super.mode = mode;
    }

    @Override
    public byte[] encapsulate() throws Exception
    {
        KyberEncrypted encapsulationWithSecret = new KyberService().encapsulate(super.mode, super.serverPublic);
        byte[] encapsulation = encapsulationWithSecret.getCipheredText();
        super.aesKey = encapsulationWithSecret.getSecretKey();
        System.out.print("[Client]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
        return encapsulation;
    }
}