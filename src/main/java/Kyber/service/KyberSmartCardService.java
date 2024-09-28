package Kyber.service;

import Kyber.Implementation.SmartCard.KyberAlgorithm;
import Kyber.Models.KeyPair;
import Kyber.Models.KyberEncrypted;
import Kyber.Models.KyberParams;

import java.security.SecureRandom;

public class KyberSmartCardService extends KyberService
{
    @Override
    public KeyPair generateKeys(int mode) throws Exception
    {
        if (mode == 512) return new KyberAlgorithm().generateKeys(2, KyberParams.Kyber512SKBytes);
        if (mode == 768) return new KyberAlgorithm().generateKeys(3, KyberParams.Kyber768SKBytes);
        if (mode == 1024) return new KyberAlgorithm().generateKeys(4, KyberParams.Kyber1024SKBytes);
        throw new RuntimeException("Mode not supported.");
    }

    @Override
    public KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception
    {
        byte[] random = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(random);
        if (mode == 512) return new KyberAlgorithm().encapsulate(random, publicKey, 2);
        if (mode == 768) return new KyberAlgorithm().encapsulate(random, publicKey, 3);
        if (mode == 1024) return new KyberAlgorithm().encapsulate(random, publicKey, 4);
        throw new RuntimeException("Mode not supported.");
    }

    @Override
    public byte[] decapsulate(int mode, byte[] privateKey, byte[] encapsulation) throws Exception
    {
        if (mode == 512) return new KyberAlgorithm().decapsulate(encapsulation, privateKey, 2, KyberParams.paramsIndcpaSecretKeyBytesK512, KyberParams.paramsIndcpaPublicKeyBytesK512, KyberParams.Kyber512SKBytes).getSecretKey();
        if (mode == 768) return new KyberAlgorithm().decapsulate(encapsulation, privateKey, 3, KyberParams.paramsIndcpaSecretKeyBytesK768, KyberParams.paramsIndcpaPublicKeyBytesK768, KyberParams.Kyber768SKBytes).getSecretKey();
        if (mode == 1024) return new KyberAlgorithm().decapsulate(encapsulation, privateKey, 4, KyberParams.paramsIndcpaSecretKeyBytesK1024, KyberParams.paramsIndcpaPublicKeyBytesK1024, KyberParams.Kyber1024SKBytes).getSecretKey();
        throw new RuntimeException("Mode not supported.");
    }
}