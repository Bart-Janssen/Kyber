package Kyber.service;

import Kyber.Implementation.Reference.KyberAlgorithm;
import Kyber.Implementation.Reference.KyberKeyPairGenerator;
import Kyber.Models.KeyPair;
import Kyber.Models.KyberEncrypted;
import java.security.SecureRandom;

public class KyberReferenceService extends KyberService
{
    @Override
    public KeyPair generateKeys(int mode) throws Exception
    {
        if (mode == 512) return new KyberKeyPairGenerator().generateKeys512(SecureRandom.getInstanceStrong());
        if (mode == 768) return new KyberKeyPairGenerator().generateKeys768(SecureRandom.getInstanceStrong());
        if (mode == 1024) return new KyberKeyPairGenerator().generateKeys1024(SecureRandom.getInstanceStrong());
        throw new RuntimeException("Mode not supported.");
    }

    @Override
    public KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception
    {
        byte[] random = new byte[32];
//        SecureRandom.getInstanceStrong().nextBytes(random);
        if (mode == 512) return new KyberAlgorithm().encrypt512(random, publicKey);
        if (mode == 768) return new KyberAlgorithm().encrypt768(random, publicKey);
        if (mode == 1024) return new KyberAlgorithm().encrypt1024(random, publicKey);
        throw new RuntimeException("Mode not supported.");
    }

    @Override
    public byte[] decapsulate(int mode, byte[] privateKey, byte[] encapsulation) throws Exception
    {
        if (mode == 512) return new KyberAlgorithm().decrypt512(encapsulation, privateKey).getSecretKey();
        if (mode == 768) return new KyberAlgorithm().decrypt768(encapsulation, privateKey).getSecretKey();
        if (mode == 1024) return new KyberAlgorithm().decrypt1024(encapsulation, privateKey).getSecretKey();
        throw new RuntimeException("Mode not supported.");
    }
}