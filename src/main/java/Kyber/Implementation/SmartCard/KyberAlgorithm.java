package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.JCSystem;
import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Implementation.SmartCard.dummy.RandomData;
import Kyber.Models.*;
import java.util.Arrays;

public class KyberAlgorithm
{
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

    protected KyberAlgorithm(byte paramsK)
    {
        this.paramsK = paramsK;
        keyPair = KeyPair.getInstance(paramsK);
    }

    private static KyberAlgorithm kyber;

    public static KyberAlgorithm getInstance(byte paramsK)
    {
        if (kyber == null) kyber = new KyberAlgorithm(paramsK);
        return kyber;
    }

    byte paramsK;
    private Keccak keccak;
    private KeyPair keyPair;
    
    //phase 2
//    public KyberEncrypted encapsulate(byte[] variant, byte[] publicKey, byte paramsK) throws Exception
//    {
//        Keccak keccak;
//        variant = verifyVariant(variant);
//        byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
//        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
//        byte[] buf1 = new byte[32];
//        keccak.doFinal(variant, buf1);
//        byte[] buf2 = new byte[32];
//        keccak.doFinal(publicKey, buf2);
//        byte[] buf3 = new byte[buf1.length + buf2.length];
//        System.arraycopy(buf1, 0, buf3, 0, buf1.length);
//        System.arraycopy(buf2, 0, buf3, buf1.length, buf2.length);
//        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
//        byte[] kr = new byte[64];
//        keccak.doFinal(buf3, kr);
//        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
//        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
//        byte[] ciphertext = this.encrypt(buf1, publicKey, subKr, paramsK);
//        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
//        byte[] krc = new byte[32];
//        keccak.doFinal(ciphertext, krc);
//        byte[] newKr = new byte[KyberParams.paramsSymBytes + krc.length];
//        System.arraycopy(kr, 0, newKr, 0, KyberParams.paramsSymBytes);
//        System.arraycopy(krc, 0, newKr, KyberParams.paramsSymBytes, krc.length);
//        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
//        keccak.setShakeDigestLength((short)32);
//        keccak.doFinal(newKr, sharedSecret);
//        return new KyberEncrypted(ciphertext, sharedSecret);
//    }

    //phase 3
//    public KyberDecrypted decapsulate(byte[] encapsulation, byte[] privateKey, byte paramsK, short secretKeyBytes, short publicKeyBytes, short privateKeyBytes) throws Exception
//    {
//        Keccak keccak;
//        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
//        byte[] indcpaPrivateKey = new byte[secretKeyBytes];
//        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.length);
//        byte[] publicKey = new byte[publicKeyBytes];
//        System.arraycopy(privateKey, secretKeyBytes, publicKey, 0, publicKey.length);
//        //buf renamed to plain
//        byte[] plain = this.decrypt(encapsulation, indcpaPrivateKey, paramsK);
//        int ski = privateKeyBytes - 2 * KyberParams.paramsSymBytes;
//        byte[] newBuf = new byte[plain.length + KyberParams.paramsSymBytes];
//        System.arraycopy(plain, 0, newBuf, 0, plain.length);
//        System.arraycopy(privateKey, ski, newBuf, plain.length, KyberParams.paramsSymBytes);
//        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
//        byte[] kr = new byte[64];
//        keccak.doFinal(newBuf, kr);
//        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
//        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
//        byte[] cmp = this.encrypt(plain, publicKey, subKr, paramsK);
//        byte fail = (byte) this.constantTimeCompare(encapsulation, cmp);
//        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
//        byte[] krh = new byte[32];
//        keccak.doFinal(encapsulation, krh);
//        int index = privateKeyBytes - KyberParams.paramsSymBytes;
//        for (int i = 0; i < KyberParams.paramsSymBytes; i++)
//        {
//            kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (privateKey[index] & 0xFF))));
//            index += 1;
//        }
//        byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
//        System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
//        System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
//        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
//        keccak.setShakeDigestLength((short)32);
//        keccak.doFinal(tempBuf, sharedSecretFixedLength);
//        return new KyberDecrypted(plain, sharedSecretFixedLength);
//    }

    //phase 3
//    public byte[] decrypt(byte[] packedCipherText, byte[] privateKey, byte paramsK)
//    {
//        UnpackedCipherText unpackedCipherText = unpackCiphertext(packedCipherText, paramsK);
//        short[][] bp = unpackedCipherText.getBp();
//        short[] v = unpackedCipherText.getV();
//        short[][] unpackedPrivateKey = unpackPrivateKey(privateKey, paramsK);
//        bp = Poly.polyVectorNTT(bp, paramsK);
//        short[] mp = Poly.polyVectorPointWiseAccMont(unpackedPrivateKey, bp, paramsK);
//        mp = Poly.polyInvNTTMont(mp);
//        mp = Poly.polySub(v, mp);
//        mp = Poly.polyReduce(mp);
//        return Poly.polyToMsg(mp);
//    }

    //phase 2
//    public byte[] encrypt(byte[] m, byte[] publicKey, byte[] coins, byte paramsK)
//    {
//        short[][] sp = Poly.generateNewPolyVector(paramsK);
//        short[][] ep = Poly.generateNewPolyVector(paramsK);
//        short[][] bp = Poly.generateNewPolyVector(paramsK);
//        UnpackedPublicKey unpackedPublicKey = unpackPublicKey(publicKey, paramsK);
//        short[] k = Poly.polyFromData(m);
//        short[][][] at = generateMatrix(Arrays.copyOfRange(unpackedPublicKey.getSeed(), 0, KyberParams.paramsSymBytes), true, paramsK);
//
//        for (byte i = 0; i < paramsK; i++)
//        {
//            sp[i] = Poly.getNoisePoly(coins, (i), paramsK);
//            ep[i] = Poly.getNoisePoly(coins, (byte) (i + paramsK), (byte)3);
//        }
//
//        short[] epp = Poly.getNoisePoly(coins, (byte) (paramsK * 2), (byte)3);
//        sp = Poly.polyVectorNTT(sp, paramsK);
//        sp = Poly.polyVectorReduce(sp, paramsK);
//        for (byte i = 0; i < paramsK; i++)
//        {
//            bp[i] = Poly.polyVectorPointWiseAccMont(at[i], sp, paramsK);
//        }
//        short[] v = Poly.polyVectorPointWiseAccMont(unpackedPublicKey.getPublicKeyPolyvec(), sp, paramsK);
//        bp = Poly.polyVectorInvNTTMont(bp, paramsK);
//        v = Poly.polyInvNTTMont(v);
//        bp = Poly.polyVectorAdd(bp, ep, paramsK);
//        v = Poly.polyAdd(Poly.polyAdd(v, epp), k);
//        bp = Poly.polyVectorReduce(bp, paramsK);
//
//        return packCiphertext(bp, Poly.polyReduce(v), paramsK);
//    }

    //phase 1
    //r = array 1 || array 1.1 || array 1.2 || array 2 || array 2.1 || array 2.2 || array 3 || array 3.1 ...
    public short[] generateMatrix(byte[] seed, boolean transposed, byte paramsK)
    {
        //2*2*384 = 1536
        short[] r = new short[paramsK*paramsK*KyberParams.paramsPolyBytes];
        byte[] buf = new byte[672];
        KyberUniformRandom uniformRandom = new KyberUniformRandom();
        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_128);
        for (byte i = 0; i < paramsK; i++)
        {
            for (byte j = 0; j < paramsK; j++)
            {
                byte[] ij = new byte[2];
                if (transposed)
                {
                    ij[0] = i;
                    ij[1] = j;
                }
                else
                {
                    ij[0] = j;
                    ij[1] = i;
                }
                byte[] seedAndij = new byte[seed.length + ij.length];
                System.arraycopy(seed, 0, seedAndij, 0, seed.length);
                System.arraycopy(ij, 0, seedAndij, seed.length, ij.length);
                keccak.reset();
                keccak.setShakeDigestLength((short)buf.length);
                keccak.doFinal(seedAndij, buf);
                generateUniform(uniformRandom, Arrays.copyOfRange(buf, 0, 504), 504, KyberParams.paramsN);
                int ui = uniformRandom.getUniformI();
                System.arraycopy(uniformRandom.getUniformR(), 0, r, ((i*2)+j)*384, 384);
                while (ui < KyberParams.paramsN)
                {
                    generateUniform(uniformRandom, Arrays.copyOfRange(buf, 504, 672), 168, KyberParams.paramsN - ui);
                    int ctrn = uniformRandom.getUniformI();
                    short[] missing = uniformRandom.getUniformR();
                    for (int k = ui; k < KyberParams.paramsN; k++)
                    {
                        r[((i * 2 + j) * 384) + k] = missing[k - ui];
                    }
                    ui = ui + ctrn;
                }
            }
        }
        return r;
    }

    //phase 3
//    public int constantTimeCompare(byte[] x, byte[] y)
//    {
//        if (x.length != y.length) return 1;
//        byte v = 0;
//        for (int i = 0; i < x.length; i++)
//        {
//            v = (byte) ((int) (v & 0xFF) | ((int) (x[i] & 0xFF) ^ (int) (y[i] & 0xFF)));
//        }
//        return Byte.compare(v, (byte) 0);
//    }

    //phase 2
//    private byte[] verifyVariant(byte[] variant) throws Exception
//    {
//        if (variant.length > KyberParams.paramsSymBytes)
//        {
//            throw new IllegalArgumentException("Byte array exceeds allowable size of " + KyberParams.paramsSymBytes + " bytes");
//        }
//        else if (variant.length < KyberParams.paramsSymBytes)
//        {
//            byte[] tempData = new byte[KyberParams.paramsSymBytes];
//            System.arraycopy(variant, 0, tempData, 0, variant.length);
//            byte[] emptyBytes = new byte[KyberParams.paramsSymBytes - variant.length];
//            for (int i = 0; i < emptyBytes.length; ++i)
//            {
//                emptyBytes[i] = (byte) 0;
//            }
//            System.arraycopy(emptyBytes, 0, tempData, variant.length, emptyBytes.length);
//            return tempData;
//        }
//        return variant;
//    }

//    //phase 1 Smart card ok
    public void generateKeys(short privateKeyBytes) throws Exception
    {
        this.generateKyberKeys();
        byte[] privateKeyFixedLength = new byte[privateKeyBytes];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] encodedHash = new byte[32];
        this.keccak.doFinal(this.keyPair.getPublicKey(), encodedHash);
        byte[] pkh = new byte[encodedHash.length];
        Util.arrayCopyNonAtomic(encodedHash, (short)0, pkh, (short)0, (short)encodedHash.length);
        byte[] rnd = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        random.nextBytes(rnd, (short)0, (short)32);
        random.close();
        short offsetEnd = (short)keyPair.getPrivateKey().length;
        Util.arrayCopyNonAtomic(this.keyPair.getPrivateKey(), (short)0, privateKeyFixedLength, (short)0, offsetEnd);
        Util.arrayCopyNonAtomic(this.keyPair.getPublicKey(), (short)0, privateKeyFixedLength, offsetEnd, (short)this.keyPair.getPublicKey().length);
        offsetEnd = (short)(offsetEnd + this.keyPair.getPublicKey().length);
        Util.arrayCopyNonAtomic(pkh, (short)0, privateKeyFixedLength, offsetEnd, (short)pkh.length);
        offsetEnd += (short)pkh.length;
        Util.arrayCopyNonAtomic(rnd, (short)0, privateKeyFixedLength, offsetEnd, (short)rnd.length);
        this.keyPair.setPrivateKey(privateKeyFixedLength);
        //priv = priv || pub || pkh (pub hash) || rnd
    }

    //phase 1
    public void generateKyberKeys() throws Exception
    {
        short[] skpv = Poly.generateNewPolyVector(this.paramsK);
        short[] pkpv = Poly.generateNewPolyVector(this.paramsK);
        short[] e = Poly.generateNewPolyVector(this.paramsK);
        byte[] publicSeed = JCSystem.makeTransientByteArray(KyberParams.paramsSymBytes, JCSystem.CLEAR_ON_DESELECT);
        byte[] noiseSeed = new byte[KyberParams.paramsSymBytes];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] fullSeed = new byte[(byte)64];
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        random.nextBytes(publicSeed, (short)0, (short)32);
        random.close();
        this.keccak.doFinal(publicSeed, fullSeed);
        Util.arrayCopyNonAtomic(fullSeed, (short)0, publicSeed, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(fullSeed, KyberParams.paramsSymBytes, noiseSeed, (short)0, KyberParams.paramsSymBytes);
        short[] a = generateMatrix(publicSeed, false, paramsK);
        byte nonce = (byte) 0;
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.arrayCopyNonAtomic(Poly.getNoisePoly(noiseSeed, nonce, paramsK), (short)0, skpv, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte) (nonce + (byte) 1);
        }
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.arrayCopyNonAtomic(Poly.getNoisePoly(noiseSeed, nonce, paramsK), (short)0, e, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte) (nonce + (byte) 1);
        }
        skpv = Poly.polyVectorNTT(skpv, paramsK);
        skpv = Poly.polyVectorReduce(skpv, paramsK);
        e = Poly.polyVectorNTT(e, paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            short[] polyArow = new short[384*paramsK];
            System.arraycopy(a, i*paramsK*384, polyArow,0,384*paramsK);
            short[] temp = Poly.polyVectorPointWiseAccMont(polyArow, skpv, paramsK);
            Poly.arrayCopyNonAtomic(Poly.polyToMont(temp), (short)0, pkpv, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
        }
        pkpv = Poly.polyVectorAdd(pkpv, e, paramsK);
        pkpv = Poly.polyVectorReduce(pkpv, paramsK);
        KeyPair keyPair = KeyPair.getInstance(paramsK);
        keyPair.setPrivateKey(this.packPrivateKey(skpv, paramsK));
        keyPair.setPublicKey(this.packPublicKey(pkpv, publicSeed, paramsK));
    }

    //phase 1
    public void generateUniform(KyberUniformRandom uniformRandom, byte[] buf, int bufl, int l)
    {
        short[] uniformR = new short[KyberParams.paramsPolyBytes];
        int d1;
        int d2;
        int uniformI = 0; // Always start at 0
        int j = 0;
        while ((uniformI < l) && ((j + 3) <= bufl))
        {
            d1 = (int) (((((int) (buf[j] & 0xFF)) >> 0) | (((int) (buf[j + 1] & 0xFF)) << 8)) & 0xFFF);
            d2 = (int) (((((int) (buf[j + 1] & 0xFF)) >> 4) | (((int) (buf[j + 2] & 0xFF)) << 4)) & 0xFFF);
            j = j + 3;
            if (d1 < (int) KyberParams.paramsQ)
            {
                uniformR[uniformI] = (short) d1;
                uniformI++;
            }
            if (uniformI < l && d2 < (int) KyberParams.paramsQ)
            {
                uniformR[uniformI] = (short) d2;
                uniformI++;
            }
        }
        uniformRandom.setUniformI(uniformI);
        uniformRandom.setUniformR(uniformR);
    }

    //phase 1
    public byte[] packPrivateKey(short[] privateKey, byte paramsK)
    {
        return Poly.polyVectorToBytes(privateKey, paramsK);
    }

    //phase 1

    public byte[] packPublicKey(short[] publicKey, byte[] seed, byte paramsK)
    {
        byte[] initialArray = Poly.polyVectorToBytes(publicKey, paramsK);
        byte[] packedPublicKey;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
            System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
            System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
            return packedPublicKey;
//            case 3:
//                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK768];
//                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
//                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
//                return packedPublicKey;
//            default:
//                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
//                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
//                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
//                return packedPublicKey;
        }
    }

    //phase 2
//    public byte[] packCiphertext(short[][] b, short[] v, byte paramsK)
//    {
//        byte[] bCompress = Poly.compressPolyVector(b, paramsK);
//        byte[] vCompress = Poly.compressPoly(v, paramsK);
//        byte[] returnArray = new byte[bCompress.length + vCompress.length];
//        System.arraycopy(bCompress, 0, returnArray, 0, bCompress.length);
//        System.arraycopy(vCompress, 0, returnArray, bCompress.length, vCompress.length);
//        return returnArray;
//    }

    //phase 3
//    public UnpackedCipherText unpackCiphertext(byte[] c, byte paramsK)
//    {
//        UnpackedCipherText unpackedCipherText = new UnpackedCipherText();
//        byte[] bpc;
//        byte[] vc;
//        switch (paramsK)
//        {
//            //Only kyber 512 for now
//            case 2: default:
//                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
//                break;
////            case 3:
////                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
////                break;
////            default:
////                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
//        }
//        System.arraycopy(c, 0, bpc, 0, bpc.length);
//        vc = new byte[c.length - bpc.length];
//        System.arraycopy(c, bpc.length, vc, 0, vc.length);
//        unpackedCipherText.setBp(Poly.decompressPolyVector(bpc, paramsK));
//        unpackedCipherText.setV(Poly.decompressPoly(vc, paramsK));
//
//        return unpackedCipherText;
//    }

    //phase 3
//    public static short[][] unpackPrivateKey(byte[] packedPrivateKey, byte paramsK)
//    {
//        return Poly.polyVectorFromBytes(packedPrivateKey, paramsK);
//    }

    //phase 2
//    public static UnpackedPublicKey unpackPublicKey(byte[] packedPublicKey, byte paramsK)
//    {
//        UnpackedPublicKey unpackedKey = new UnpackedPublicKey();
//        switch (paramsK)
//        {
//            //Only kyber 512 for now
//            case 2: default:
//                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK512), paramsK));
//                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK512, packedPublicKey.length));
//                break;
////            case 3:
////                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK768), paramsK));
////                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK768, packedPublicKey.length));
////                break;
////            default:
////                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK1024), paramsK));
////                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK1024, packedPublicKey.length));
//        }
//        return unpackedKey;
//    }
}