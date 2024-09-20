package Kyber;

import Kyber.Algorithm.*;
import java.security.SecureRandom;

public class KyberService
{
    public KeyPair generateKeys(int mode) throws Exception
    {
        if (mode == 512) return new KyberKeyPairGenerator().generateKeys512(SecureRandom.getInstanceStrong());
        if (mode == 768) return new KyberKeyPairGenerator().generateKeys768(SecureRandom.getInstanceStrong());
        if (mode == 1024) return new KyberKeyPairGenerator().generateKeys1024(SecureRandom.getInstanceStrong());
        throw new RuntimeException("Mode not supported.");
    }

    public KyberEncrypted generateSecretKeyClient(int mode, byte[] publicKey) throws Exception
    {
        byte[] random = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(random);
        if (mode == 512) return new KyberAlgorithm().encrypt512(random, publicKey);
        if (mode == 768) return new KyberAlgorithm().encrypt768(random, publicKey);
        if (mode == 1024) return new KyberAlgorithm().encrypt1024(random, publicKey);
        throw new RuntimeException("Mode not supported.");
    }

    public byte[] decapsulate(int mode, byte[] privateKey, byte[] encapsulation) throws Exception
    {
        byte[] sharedSecret;
        KyberDecrypted kyberDecrypted = this.extractSecret(mode, privateKey, encapsulation);
        sharedSecret = kyberDecrypted.getSecretKey();
        return sharedSecret;
    }

    private KyberDecrypted extractSecret(int mode, byte[] privateKey, byte[] encapsulation) throws Exception
    {
        if (mode == 512) return new KyberAlgorithm().decrypt512(encapsulation, privateKey);
        if (mode == 768) return new KyberAlgorithm().decrypt768(encapsulation, privateKey);
        if (mode == 1024) return new KyberAlgorithm().decrypt1024(encapsulation, privateKey);
        throw new RuntimeException("Mode not supported.");
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