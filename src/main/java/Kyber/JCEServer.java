package Kyber;

import Kyber.Models.KeyPair;
import Kyber.service.KyberReferenceService;

public class JCEServer extends Server
{
    public JCEServer(int mode) throws Exception
    {
        super(mode);
        KeyPair keyPair = new KyberReferenceService().generateKeys(super.mode);
        super.privateKey = keyPair.getPrivateKey();
        super.publicKey = keyPair.getPublicKey();
        System.out.print("[Server]  : Public Key length: " + super.publicKey.length + " | ");super.print(super.publicKey);
        System.out.print("[Server]  : Private Key length: " + super.privateKey.length + " | ");super.print(super.privateKey);
    }

    @Override
    public void decapsulate(byte[] encapsulation) throws Exception
    {
        super.aesKey = new KyberReferenceService().decapsulate(super.mode, super.privateKey, encapsulation);
        System.out.print("[Server]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
    }

    @Override
    public byte[] getPublic()
    {
        return super.publicKey;
    }
}