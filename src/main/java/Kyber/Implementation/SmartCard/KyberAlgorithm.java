package Kyber.Implementation.SmartCard;

import Kyber.Models.*;
import java.util.Arrays;

public class KyberAlgorithm
{
    public KyberEncrypted encrypt512(byte[] variant, byte[] publicKey) throws Exception
    {
        Keccak keccak;
        variant = verifyVariant(variant);
        int paramsK = 2;
        byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] buf1 = new byte[32];
        keccak.doFinal(variant, buf1);
        byte[] buf2 = new byte[32];
        keccak.doFinal(publicKey, buf2);
        byte[] buf3 = new byte[buf1.length + buf2.length];
        System.arraycopy(buf1, 0, buf3, 0, buf1.length);
        System.arraycopy(buf2, 0, buf3, buf1.length, buf2.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        keccak.doFinal(buf3, kr);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] ciphertext = this.encrypt(buf1, publicKey, subKr, paramsK);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krc = new byte[32];
        keccak.doFinal(ciphertext, krc);
        byte[] newKr = new byte[KyberParams.paramsSymBytes + krc.length];
        System.arraycopy(kr, 0, newKr, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krc, 0, newKr, KyberParams.paramsSymBytes, krc.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength((short)32);
        keccak.doFinal(newKr, sharedSecret);
        return new KyberEncrypted(ciphertext, sharedSecret);
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

    public KyberDecrypted decrypt512(byte[] ciphertext, byte[] privateKey) throws Exception
    {
        Keccak keccak;
        int paramsK = 2;
        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        byte[] indcpaPrivateKey = new byte[KyberParams.paramsIndcpaSecretKeyBytesK512];
        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.length);
        byte[] publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
        System.arraycopy(privateKey, KyberParams.paramsIndcpaSecretKeyBytesK512, publicKey, 0, publicKey.length);
        //buf renamed to plain
        byte[] plain = this.decrypt(ciphertext, indcpaPrivateKey, paramsK);
        int ski = KyberParams.Kyber512SKBytes - 2 * KyberParams.paramsSymBytes;
        byte[] newBuf = new byte[plain.length + KyberParams.paramsSymBytes];
        System.arraycopy(plain, 0, newBuf, 0, plain.length);
        System.arraycopy(privateKey, ski, newBuf, plain.length, KyberParams.paramsSymBytes);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        keccak.doFinal(newBuf, kr);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] cmp = this.encrypt(plain, publicKey, subKr, paramsK);
        byte fail = (byte) this.constantTimeCompare(ciphertext, cmp);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krh = new byte[32];
        keccak.doFinal(ciphertext, krh);
        int index = KyberParams.Kyber512SKBytes - KyberParams.paramsSymBytes;
        for (int i = 0; i < KyberParams.paramsSymBytes; i++)
        {
            kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (privateKey[index] & 0xFF))));
            index += 1;
        }
        byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
        System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength((short)32);
        keccak.doFinal(tempBuf, sharedSecretFixedLength);
        return new KyberDecrypted(plain, sharedSecretFixedLength);
    }

    public KyberEncrypted encrypt768(byte[] variant, byte[] publicKey) throws Exception
    {
        Keccak keccak;
        variant = verifyVariant(variant);
        int paramsK = 3;
        byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] buf1 = new byte[32];
        keccak.doFinal(variant, buf1);
        byte[] buf2 = new byte[32];
        keccak.doFinal(publicKey, buf2);
        byte[] buf3 = new byte[buf1.length + buf2.length];
        System.arraycopy(buf1, 0, buf3, 0, buf1.length);
        System.arraycopy(buf2, 0, buf3, buf1.length, buf2.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        keccak.doFinal(buf3, kr);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] ciphertext = this.encrypt(buf1, publicKey, subKr, paramsK);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krc = new byte[32];
        keccak.doFinal(ciphertext, krc);
        byte[] newKr = new byte[KyberParams.paramsSymBytes + krc.length];
        System.arraycopy(kr, 0, newKr, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krc, 0, newKr, KyberParams.paramsSymBytes, krc.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength((short)32);
        keccak.doFinal(newKr, sharedSecret);
        return new KyberEncrypted(ciphertext, sharedSecret);
    }

    public KyberDecrypted decrypt768(byte[] encapsulation, byte[] privateKey) throws Exception
    {
        Keccak keccak;
        int paramsK = 3;
        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        byte[] indcpaPrivateKey = new byte[KyberParams.paramsIndcpaSecretKeyBytesK768];
        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.length);
        byte[] publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK768];
        System.arraycopy(privateKey, KyberParams.paramsIndcpaSecretKeyBytesK768, publicKey, 0, publicKey.length);

        //buf renamed to plain
        byte[] plain = this.decrypt(encapsulation, indcpaPrivateKey, paramsK);
        int ski = KyberParams.Kyber768SKBytes - 2 * KyberParams.paramsSymBytes;
        byte[] newBuf = new byte[plain.length + KyberParams.paramsSymBytes];
        System.arraycopy(plain, 0, newBuf, 0, plain.length);
        System.arraycopy(privateKey, ski, newBuf, plain.length, KyberParams.paramsSymBytes);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        keccak.doFinal(newBuf, kr);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] cmp = this.encrypt(plain, publicKey, subKr, paramsK);
        byte fail = (byte) this.constantTimeCompare(encapsulation, cmp);
        // For security purposes, removed the "if" so it behaves the same whether it
        // worked or not.
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krh = new byte[32];
        keccak.doFinal(encapsulation, krh);
        int index = KyberParams.Kyber768SKBytes - KyberParams.paramsSymBytes;
        for (int i = 0; i < KyberParams.paramsSymBytes; i++)
        {
            kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (privateKey[index] & 0xFF))));
            index += 1;
        }
        byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
        System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength((short)32);
        keccak.doFinal(tempBuf, sharedSecretFixedLength);
        return new KyberDecrypted(plain, sharedSecretFixedLength);
    }

    public KyberEncrypted encrypt1024(byte[] variant, byte[] publicKey) throws Exception
    {
        Keccak keccak;
        variant = verifyVariant(variant);
        int paramsK = 4;
        byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] buf1 = new byte[32];
        keccak.doFinal(variant, buf1);
        byte[] buf2 = new byte[32];
        keccak.doFinal(publicKey, buf2);
        byte[] buf3 = new byte[buf1.length + buf2.length];
        System.arraycopy(buf1, 0, buf3, 0, buf1.length);
        System.arraycopy(buf2, 0, buf3, buf1.length, buf2.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        keccak.doFinal(buf3, kr);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] ciphertext = this.encrypt(buf1, publicKey, subKr, paramsK);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krc = new byte[32];
        keccak.doFinal(ciphertext, krc);
        byte[] newKr = new byte[KyberParams.paramsSymBytes + krc.length];
        System.arraycopy(kr, 0, newKr, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krc, 0, newKr, KyberParams.paramsSymBytes, krc.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength((short)32);
        keccak.doFinal(newKr, sharedSecret);
        return new KyberEncrypted(ciphertext, sharedSecret);
    }

    public KyberDecrypted decrypt1024(byte[] encapsulation, byte[] privateKey) throws Exception
    {
        Keccak keccak;
        int paramsK = 4;
        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        byte[] indcpaPrivateKey = new byte[KyberParams.paramsIndcpaSecretKeyBytesK1024];
        System.arraycopy(privateKey, 0, indcpaPrivateKey, 0, indcpaPrivateKey.length);
        byte[] publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
        System.arraycopy(privateKey, KyberParams.paramsIndcpaSecretKeyBytesK1024, publicKey, 0, publicKey.length);

        //renamed buf to plain
        byte[] plain = this.decrypt(encapsulation, indcpaPrivateKey, paramsK);
        int ski = KyberParams.Kyber1024SKBytes - 2 * KyberParams.paramsSymBytes;
        byte[] newBuf = new byte[plain.length + KyberParams.paramsSymBytes];
        System.arraycopy(plain, 0, newBuf, 0, plain.length);
        System.arraycopy(privateKey, ski, newBuf, plain.length, KyberParams.paramsSymBytes);
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        keccak.doFinal(newBuf, kr);
        byte[] subKr = new byte[kr.length - KyberParams.paramsSymBytes];
        System.arraycopy(kr, KyberParams.paramsSymBytes, subKr, 0, subKr.length);
        byte[] cmp = this.encrypt(plain, publicKey, subKr, paramsK);
        byte fail = (byte) this.constantTimeCompare(encapsulation, cmp);
        // For security purposes, removed the "if" so it behaves the same whether it
        // worked or not.
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krh = new byte[32];
        keccak.doFinal(encapsulation, krh);
        int index = KyberParams.Kyber1024SKBytes - KyberParams.paramsSymBytes;
        for (int i = 0; i < KyberParams.paramsSymBytes; i++)
        {
            kr[i] = (byte) ((int) (kr[i] & 0xFF) ^ ((int) (fail & 0xFF) & ((int) (kr[i] & 0xFF) ^ (int) (privateKey[index] & 0xFF))));
            index += 1;
        }
        byte[] tempBuf = new byte[KyberParams.paramsSymBytes + krh.length];
        System.arraycopy(kr, 0, tempBuf, 0, KyberParams.paramsSymBytes);
        System.arraycopy(krh, 0, tempBuf, KyberParams.paramsSymBytes, krh.length);
        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength((short)32);
        keccak.doFinal(tempBuf, sharedSecretFixedLength);
        return new KyberDecrypted(plain, sharedSecretFixedLength);
    }

    public byte[] decrypt(byte[] packedCipherText, byte[] privateKey, int paramsK)
    {
        UnpackedCipherText unpackedCipherText = unpackCiphertext(packedCipherText, paramsK);
        short[][] bp = unpackedCipherText.getBp();
        short[] v = unpackedCipherText.getV();
        short[][] unpackedPrivateKey = unpackPrivateKey(privateKey, paramsK);
        bp = Poly.polyVectorNTT(bp, paramsK);
        short[] mp = Poly.polyVectorPointWiseAccMont(unpackedPrivateKey, bp, paramsK);
        mp = Poly.polyInvNTTMont(mp);
        mp = Poly.polySub(v, mp);
        mp = Poly.polyReduce(mp);
        return Poly.polyToMsg(mp);
    }

    public UnpackedCipherText unpackCiphertext(byte[] c, int paramsK)
    {
        UnpackedCipherText unpackedCipherText = new UnpackedCipherText();
        byte[] bpc;
        byte[] vc;
        switch (paramsK)
        {
            case 2:
                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
            case 3:
                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
                break;
            default:
                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        }
        System.arraycopy(c, 0, bpc, 0, bpc.length);
        vc = new byte[c.length - bpc.length];
        System.arraycopy(c, bpc.length, vc, 0, vc.length);
        unpackedCipherText.setBp(Poly.decompressPolyVector(bpc, paramsK));
        unpackedCipherText.setV(Poly.decompressPoly(vc, paramsK));

        return unpackedCipherText;
    }

    public static short[][] unpackPrivateKey(byte[] packedPrivateKey, int paramsK)
    {
        short[][] unpackedPrivateKey = Poly.polyVectorFromBytes(packedPrivateKey, paramsK);
        return unpackedPrivateKey;
    }

    public byte[] encrypt(byte[] m, byte[] publicKey, byte[] coins, int paramsK)
    {
        short[][] sp = Poly.generateNewPolyVector(paramsK);
        short[][] ep = Poly.generateNewPolyVector(paramsK);
        short[][] bp = Poly.generateNewPolyVector(paramsK);
        UnpackedPublicKey unpackedPublicKey = unpackPublicKey(publicKey, paramsK);
        short[] k = Poly.polyFromData(m);
        short[][][] at = generateMatrix(Arrays.copyOfRange(unpackedPublicKey.getSeed(), 0, KyberParams.paramsSymBytes), true, paramsK);

        for (int i = 0; i < paramsK; i++)
        {
            sp[i] = Poly.getNoisePoly(coins, (byte) (i), paramsK);
            ep[i] = Poly.getNoisePoly(coins, (byte) (i + paramsK), 3);
        }

        short[] epp = Poly.getNoisePoly(coins, (byte) (paramsK * 2), 3);
        sp = Poly.polyVectorNTT(sp, paramsK);
        sp = Poly.polyVectorReduce(sp, paramsK);
        for (int i = 0; i < paramsK; i++)
        {
            bp[i] = Poly.polyVectorPointWiseAccMont(at[i], sp, paramsK);
        }
        short[] v = Poly.polyVectorPointWiseAccMont(unpackedPublicKey.getPublicKeyPolyvec(), sp, paramsK);
        bp = Poly.polyVectorInvNTTMont(bp, paramsK);
        v = Poly.polyInvNTTMont(v);
        bp = Poly.polyVectorAdd(bp, ep, paramsK);
        v = Poly.polyAdd(Poly.polyAdd(v, epp), k);
        bp = Poly.polyVectorReduce(bp, paramsK);

        return packCiphertext(bp, Poly.polyReduce(v), paramsK);
    }

    public static UnpackedPublicKey unpackPublicKey(byte[] packedPublicKey, int paramsK)
    {
        UnpackedPublicKey unpackedKey = new UnpackedPublicKey();
        switch (paramsK)
        {
            case 2:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK512), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK512, packedPublicKey.length));
                break;
            case 3:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK768), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK768, packedPublicKey.length));
                break;
            default:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK1024), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK1024, packedPublicKey.length));
        }
        return unpackedKey;
    }

    public short[][][] generateMatrix(byte[] seed, boolean transposed, int paramsK)
    {
        short[][][] r = new short[paramsK][paramsK][KyberParams.paramsPolyBytes];
        byte[] buf = new byte[672];
        KyberUniformRandom uniformRandom = new KyberUniformRandom();
        Keccak keccak = Keccak.getInstance(Keccak.ALG_SHAKE_128);
        for (int i = 0; i < paramsK; i++)
        {
            r[i] = Poly.generateNewPolyVector(paramsK);
            for (int j = 0; j < paramsK; j++)
            {
                byte[] ij = new byte[2];
                if (transposed)
                {
                    ij[0] = (byte) i;
                    ij[1] = (byte) j;
                }
                else
                {
                    ij[0] = (byte) j;
                    ij[1] = (byte) i;
                }
                byte[] seedAndij = new byte[seed.length + ij.length];
                System.arraycopy(seed, 0, seedAndij, 0, seed.length);
                System.arraycopy(ij, 0, seedAndij, seed.length, ij.length);
                keccak.reset();
                keccak.setShakeDigestLength((short)buf.length);
                keccak.doFinal(seedAndij, buf);
                generateUniform(uniformRandom, Arrays.copyOfRange(buf, 0, 504), 504, KyberParams.paramsN);
                int ui = uniformRandom.getUniformI();
                r[i][j] = uniformRandom.getUniformR();
                while (ui < KyberParams.paramsN)
                {
                    generateUniform(uniformRandom, Arrays.copyOfRange(buf, 504, 672), 168, KyberParams.paramsN - ui);
                    int ctrn = uniformRandom.getUniformI();
                    short[] missing = uniformRandom.getUniformR();
                    for (int k = ui; k < KyberParams.paramsN; k++)
                    {
                        r[i][j][k] = missing[k - ui];
                    }
                    ui = ui + ctrn;
                }
            }
        }
        return r;
    }

    public static void generateUniform(KyberUniformRandom uniformRandom, byte[] buf, int bufl, int l)
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

    public static byte[] packCiphertext(short[][] b, short[] v, int paramsK)
    {
        byte[] bCompress = Poly.compressPolyVector(b, paramsK);
        byte[] vCompress = Poly.compressPoly(v, paramsK);
        byte[] returnArray = new byte[bCompress.length + vCompress.length];
        System.arraycopy(bCompress, 0, returnArray, 0, bCompress.length);
        System.arraycopy(vCompress, 0, returnArray, bCompress.length, vCompress.length);
        return returnArray;
    }

    public int constantTimeCompare(byte[] x, byte[] y)
    {
        if (x.length != y.length) return 1;
        byte v = 0;
        for (int i = 0; i < x.length; i++)
        {
            v = (byte) ((int) (v & 0xFF) | ((int) (x[i] & 0xFF) ^ (int) (y[i] & 0xFF)));
        }
        return Byte.compare(v, (byte) 0);
    }

    private byte[] verifyVariant(byte[] variant) throws Exception
    {
        if (variant.length > KyberParams.paramsSymBytes)
        {
            throw new IllegalArgumentException("Byte array exceeds allowable size of " + KyberParams.paramsSymBytes + " bytes");
        }
        else if (variant.length < KyberParams.paramsSymBytes)
        {
            byte[] tempData = new byte[KyberParams.paramsSymBytes];
            System.arraycopy(variant, 0, tempData, 0, variant.length);
            byte[] emptyBytes = new byte[KyberParams.paramsSymBytes - variant.length];
            for (int i = 0; i < emptyBytes.length; ++i)
            {
                emptyBytes[i] = (byte) 0;
            }
            System.arraycopy(emptyBytes, 0, tempData, variant.length, emptyBytes.length);
            return tempData;
        }
        return variant;
    }
}