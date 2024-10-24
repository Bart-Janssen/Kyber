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
        this.keyPair = KeyPair.getInstance(paramsK);
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

    private short[] uniformR;
    private short uniformI = 0;

    public byte[] cipheredText;
    public byte[] secretKey;

    private short[] publicKeyPolyvec;
    private byte[] seed;
    
    //phase 2
    public void encapsulate() throws Exception
    {
        byte[] variant = new byte[32];
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//        random.nextBytes(variant, (short)0, (short)32);
        random.close();
        byte[] publicKey = KeyPair.getInstance((byte)2).publicKey;

        byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] buf1 = new byte[32];
        this.keccak.doFinal(variant, buf1);
        byte[] buf2 = new byte[32];
        this.keccak.doFinal(publicKey, buf2);
        byte[] buf3 = new byte[(short)(buf1.length + buf2.length)];
        Util.arrayCopyNonAtomic(buf1, (short)0, buf3, (short)0, (short)buf1.length);
        Util.arrayCopyNonAtomic(buf2, (short)0, buf3, (short)buf1.length, (short)buf2.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        this.keccak.doFinal(buf3, kr);
        byte[] subKr = new byte[(short)(kr.length - KyberParams.paramsSymBytes)];
        Util.arrayCopyNonAtomic(kr, KyberParams.paramsSymBytes, subKr, (short)0, (short)subKr.length);
        byte[] ciphertext = this.encrypt(buf1, publicKey, subKr);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krc = new byte[32];
        this.keccak.doFinal(ciphertext, krc);
        byte[] newKr = new byte[(short)(KyberParams.paramsSymBytes + krc.length)];
        Util.arrayCopyNonAtomic(kr, (short)0, newKr, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(krc, (short)0, newKr, KyberParams.paramsSymBytes, (short)krc.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        this.keccak.setShakeDigestLength((short)32);
        this.keccak.doFinal(newKr, sharedSecret);
        this.cipheredText = ciphertext;//dont do this, use it as reference
        this.secretKey = sharedSecret;//dont do this, use it as reference
    }

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

    //phase 2, is already rewritten in poly
    public static short[][] generateNewPolyVector(int paramsK) {
        short[][] pv = new short[paramsK][KyberParams.paramsPolyBytes];
        return pv;
    }

    //phase 2, is already rewritten in poly
    public static short[][] polyVectorNTT(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.getInstance().polyNTT(r[i]);
        }
        return r;
    }

    public static short[][] polyVectorReduce(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.getInstance().polyReduce(r[i]);
        }
        return r;
    }

    //phase 2 smart card ok
    public byte[] encrypt(byte[] m, byte[] publicKey, byte[] coins)
    {
        short[] sp = Poly.getInstance().generateNewPolyVector(paramsK);
        short[] ep = Poly.getInstance().generateNewPolyVector(paramsK);
        short[] bp = Poly.getInstance().generateNewPolyVector(paramsK);
        short[] k = Poly.getInstance().polyFromData(m);
        this.unpackPublicKey(publicKey, paramsK);
        byte[] partlySeed = new byte[KyberParams.paramsSymBytes];//Opt this away
        Util.arrayCopyNonAtomic(this.seed, (short)0, partlySeed, (short)0, KyberParams.paramsSymBytes);
        short[] at = this.generateMatrix(partlySeed, true);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(coins, i, paramsK), (short)0, sp,(short)(i*384),(short)384);
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(coins, (byte)(i + paramsK), (byte)3), (short)0, ep,(short)(i*384),(short)384);
        }
        short[] epp = Poly.getInstance().getNoisePoly(coins, (byte)(paramsK * 2), (byte)3);
        sp = Poly.getInstance().polyVectorNTT(sp,paramsK);
        sp = Poly.getInstance().polyVectorReduce(sp,paramsK);
        short[] polyArow = new short[(short)(384*paramsK)];
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(at, (short)(i*paramsK*384), polyArow,(short)0,(short)(384*paramsK));
            short[] temp = Poly.getInstance().polyVectorPointWiseAccMont(polyArow, sp, paramsK);
            Poly.getInstance().arrayCopyNonAtomic(temp, (short)0,bp,(short)(i*384),(short)384);
        }
        short[] v = Poly.getInstance().polyVectorPointWiseAccMont(this.publicKeyPolyvec, sp, paramsK);
        bp = Poly.getInstance().polyVectorInvNTTMont(bp, paramsK);
        v = Poly.getInstance().polyInvNTTMont(v);
        bp = Poly.getInstance().polyVectorAdd(bp, ep, paramsK);
        v = Poly.getInstance().polyAdd(Poly.getInstance().polyAdd(v, epp), k);
        bp = Poly.getInstance().polyVectorReduce(bp, paramsK);
        return this.packCiphertext(bp, Poly.getInstance().polyReduce(v), paramsK);
    }

    //phase 1 smart card ok, need optimization
    //r = array 1 || array 1.1 || array 1.2 || array 2 || array 2.1 || array 2.2 || array 3 || array 3.1 ...
    public short[] generateMatrix(byte[] seed, boolean transposed)
    {
        //2*2*384 = 1536
        short[] r = new short[(short)(this.paramsK*this.paramsK*KyberParams.paramsPolyBytes)];
        byte[] buf = new byte[672];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_128);
        byte[] buff = new byte[672];//why are there 2 bufs ?
        for (byte i = 0; i < this.paramsK; i++)
        {
            for (byte j = 0; j < this.paramsK; j++)
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
                byte[] seedAndij = new byte[(short)(seed.length + ij.length)];
                Util.arrayCopyNonAtomic(seed, (short)0, seedAndij, (short)0, (short)seed.length);
                Util.arrayCopyNonAtomic(ij, (short)0, seedAndij, (short)seed.length, (short)ij.length);
                this.keccak.reset();
                this.keccak.setShakeDigestLength((short)buf.length);
                this.keccak.doFinal(seedAndij, buf);
                Util.arrayCopyNonAtomic(buf,(short)0, buff,(short)0, (short)504);
                this.generateUniform(buff, (short)504, KyberParams.paramsN);
                short ui = this.uniformI;
                Poly.getInstance().arrayCopyNonAtomic(this.uniformR, (short)0, r, (short)(((i*2)+j)*384), (short)384);
                while (ui < KyberParams.paramsN)//Occasionally, this code is not always executed
                {
                    Util.arrayCopyNonAtomic(buf,(short)504, buff,(short)0, (short)168);
                    this.generateUniform(buff, (short)168, (short)(KyberParams.paramsN - ui));
                    short ctrn = this.uniformI;
                    short[] missing = this.uniformR;
                    for (short k = ui; k < KyberParams.paramsN; k++)
                    {
                        r[(short)(((i * 2 + j) * 384) + k)] = missing[(short)(k - ui)];
                    }
                    ui += ctrn;
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

    //phase 2, makes sure variant is always 32 bytes, this function is ignored since we are always sure it is
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

    //smart card ok, need opt
    public void generateKeys(short privateKeyBytes) throws Exception
    {
        this.generateKyberKeys();
        byte[] privateKeyFixedLength = new byte[privateKeyBytes];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] encodedHash = new byte[32];
        this.keccak.doFinal(this.keyPair.publicKey, encodedHash);
        byte[] pkh = new byte[encodedHash.length];
        Util.arrayCopyNonAtomic(encodedHash, (short)0, pkh, (short)0, (short)encodedHash.length);
        byte[] rnd = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
//            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//            random.nextBytes(rnd, (short)0, (short)32);
//            random.close();
        short offsetEnd = (short)keyPair.privateKey.length;
        Util.arrayCopyNonAtomic(this.keyPair.privateKey, (short)0, privateKeyFixedLength, (short)0, offsetEnd);
        Util.arrayCopyNonAtomic(this.keyPair.publicKey, (short)0, privateKeyFixedLength, offsetEnd, (short)this.keyPair.publicKey.length);
        offsetEnd = (short)(offsetEnd + this.keyPair.publicKey.length);
        Util.arrayCopyNonAtomic(pkh, (short)0, privateKeyFixedLength, offsetEnd, (short)pkh.length);
        offsetEnd += (short)pkh.length;
        Util.arrayCopyNonAtomic(rnd, (short)0, privateKeyFixedLength, offsetEnd, (short)rnd.length);
        this.keyPair.privateKey = privateKeyFixedLength;
        //priv = priv || pub || pkh (pub hash) || rnd
    }

    //phase 1
    //smart card ok, need opt
    public void generateKyberKeys() throws Exception
    {
        short[] skpv = Poly.getInstance().generateNewPolyVector(this.paramsK);
        short[] pkpv = Poly.getInstance().generateNewPolyVector(this.paramsK);
        short[] e = Poly.getInstance().generateNewPolyVector(this.paramsK);
        byte[] publicSeed = JCSystem.makeTransientByteArray(KyberParams.paramsSymBytes, JCSystem.CLEAR_ON_DESELECT);
        byte[] noiseSeed = new byte[KyberParams.paramsSymBytes];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] fullSeed = new byte[(byte)64];
//        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//        random.nextBytes(publicSeed, (short)0, (short)32);
//        random.close();
        this.keccak.doFinal(publicSeed, fullSeed);
        Util.arrayCopyNonAtomic(fullSeed, (short)0, publicSeed, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(fullSeed, KyberParams.paramsSymBytes, noiseSeed, (short)0, KyberParams.paramsSymBytes);
        short[] a = this.generateMatrix(publicSeed, false);
        byte nonce = (byte)0;
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(noiseSeed, nonce, paramsK), (short)0, skpv, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(noiseSeed, nonce, paramsK), (short)0, e, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        skpv = Poly.getInstance().polyVectorNTT(skpv, paramsK);
        skpv = Poly.getInstance().polyVectorReduce(skpv, paramsK);
        e = Poly.getInstance().polyVectorNTT(e, paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            short[] polyArow = new short[(short)(384*paramsK)];
            Poly.getInstance().arrayCopyNonAtomic(a, (short)(i*paramsK*384), polyArow,(short)0,(short)(384*paramsK));
            short[] temp = Poly.getInstance().polyVectorPointWiseAccMont(polyArow, skpv, paramsK);
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().polyToMont(temp), (short)0, pkpv, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
        }
        pkpv = Poly.getInstance().polyVectorAdd(pkpv, e, paramsK);
        pkpv = Poly.getInstance().polyVectorReduce(pkpv, paramsK);
        KeyPair keyPair = KeyPair.getInstance(paramsK);
        keyPair.privateKey = this.packPrivateKey(skpv, paramsK);
        keyPair.publicKey = this.packPublicKey(pkpv, publicSeed, paramsK);
    }

    //phase 1 smart card ok, need optimizing
    public void generateUniform(byte[] buf, short bufl, short l)
    {
        short[] uniformR = new short[KyberParams.paramsPolyBytes];
        short d1;
        short d2;
        short uniformI = 0; // Always start at 0
        short j = 0;
        while ((uniformI < l) && ((short)(j + 3) <= bufl))
        {
            d1 = (short)(((buf[j] & 0xFF) | ((buf[(short)(j + 1)] & 0xFF) << 8)) & 0xFFF);
            d2 = (short)((((buf[(short)(j + 1)] & 0xFF) >> 4) | ((buf[(short)(j + 2)] & 0xFF) << 4)) & 0xFFF);
            j+=3;
            if (d1 < KyberParams.paramsQ)
            {
                uniformR[uniformI] = d1;
                uniformI++;
            }
            if (uniformI < l && d2 < KyberParams.paramsQ)
            {
                uniformR[uniformI] = d2;
                uniformI++;
            }
        }
        this.uniformI = uniformI;
        this.uniformR = uniformR;
    }

    //phase 1
    //smart card ok
    public byte[] packPrivateKey(short[] privateKey, byte paramsK)
    {
        return Poly.getInstance().polyVectorToBytes(privateKey, paramsK);
    }

    //phase 1
    //smart card ok, need opt
    public byte[] packPublicKey(short[] publicKey, byte[] seed, byte paramsK)
    {
        byte[] initialArray = Poly.getInstance().polyVectorToBytes(publicKey, paramsK);
        byte[] packedPublicKey;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
            Util.arrayCopyNonAtomic(initialArray, (short)0, packedPublicKey, (short)0, (short)initialArray.length);
            Util.arrayCopyNonAtomic(seed, (short)0, packedPublicKey, (short)initialArray.length, (short)seed.length);
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
    public byte[] packCiphertext(short[] b, short[] v, byte paramsK)
    {
        byte[] bCompress = Poly.getInstance().compressPolyVector(b, paramsK);
        byte[] vCompress = Poly.getInstance().compressPoly(v, paramsK);
        byte[] returnArray = new byte[(short)(bCompress.length + vCompress.length)];
        Util.arrayCopyNonAtomic(bCompress, (short)0, returnArray, (short)0, (short)bCompress.length);
        Util.arrayCopyNonAtomic(vCompress, (short)0, returnArray, (short)bCompress.length, (short)vCompress.length);
        return returnArray;
    }

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

    //phase 2 smart card ok, check seed
    public void unpackPublicKey(byte[] packedPublicKey, byte paramsK)
    {
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
                byte[] partlyPublicKey = new byte[KyberParams.paramsPolyvecBytesK512];
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, partlyPublicKey, (short)0, KyberParams.paramsPolyvecBytesK512);
                this.publicKeyPolyvec = Poly.getInstance().polyVectorFromBytes(partlyPublicKey, paramsK);
                this.seed = new byte[32];//is this always 32?
                Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK512, this.seed, (short)0, (short)32);
                break;
//            case 3:
//                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK768), paramsK));
//                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK768, packedPublicKey.length));
//                break;
//            default:
//                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK1024), paramsK));
//                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK1024, packedPublicKey.length));
        }
    }
}