package Kyber.service;

import Kyber.Models.KeyPair;
import Kyber.Models.KyberEncrypted;
import Kyber.Implementation.Reference.KyberAlgorithm;
import Kyber.Implementation.Reference.KyberKeyPairGenerator;

import java.security.SecureRandom;

public abstract class KyberService
{
    public abstract KeyPair generateKeys(int mode) throws Exception;
    public abstract KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception;
    public abstract byte[] decapsulate(int mode, byte[] privateKey, byte[] encapsulation) throws Exception;

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