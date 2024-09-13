package Kyber;

import Kyber.Algorithm.KyberAlgorithm;
import Kyber.Algorithm.KyberEncrypted;

import java.security.*;

public class JCEClient extends Client
{
    @Override
    public byte[] encapsulate() throws Exception
    {
        KyberEncrypted encapsulationWithSecret = this.generateSecretKeyClient();
        byte[] encapsulation = encapsulationWithSecret.getCipheredText();
        this.aesKey = encapsulationWithSecret.getSecretKey();
        System.out.print("[Client]  : Decapsulated secret: " + this.aesKey.length + " | ");print(aesKey);
        return encapsulation;
    }

    private KyberEncrypted generateSecretKeyClient() throws Exception
    {
        byte[] random = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(random);
        return new KyberAlgorithm().encrypt512(random, this.serverPublic);
    }

    @Override
    public String encryptAES(String plainText) throws Exception
    {
        return new AES().encryptAES(plainText, super.aesKey);
    }

    protected void print(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : data)
        {
            sb.append(String.format("%02X ", b));
        }
        System.out.print(sb);
        System.out.println();
    }
}