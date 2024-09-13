package Kyber;

import Kyber.Algorithm.KeyPair;
import Kyber.Algorithm.KyberAlgorithm;
import Kyber.Algorithm.KyberDecrypted;
import Kyber.Algorithm.KyberKeyPairGenerator;

import java.security.*;

public class JCEServer extends Server
{
    public JCEServer() throws Exception
    {
        this.generateKeyPair();
    }

    private void generateKeyPair() throws Exception
    {
        KeyPair keyPair = new KyberKeyPairGenerator().generateKeys512(SecureRandom.getInstanceStrong());
        super.privateKey = keyPair.getPrivateKey();
        super.publicKey = keyPair.getPublicKey();
        System.out.print("[Server]  : Public Key length: " + super.publicKey.length + " | ");print(super.publicKey);
        System.out.print("[Server]  : Private Key length: " + super.privateKey.length + " | ");print(super.privateKey);
    }

    @Override
    public void decapsulate(byte[] encapsulation) throws Exception
    {
        KyberDecrypted kyberDecrypted = this.extractSecret(encapsulation);
        this.aesKey = kyberDecrypted.getSecretKey();
        System.out.print("[Server]  : Decapsulated secret: " + this.aesKey.length + " | ");print(this.aesKey);
    }

    private KyberDecrypted extractSecret(byte[] encapsulation) throws Exception
    {
        return new KyberAlgorithm().decrypt512(encapsulation, super.privateKey);
    }

    @Override
    public String decryptAES(String encryptedText) throws Exception
    {
        return new AES().decryptAES(encryptedText, super.aesKey);
    }

    @Override
    public byte[] getPublic()
    {
        return super.publicKey;
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