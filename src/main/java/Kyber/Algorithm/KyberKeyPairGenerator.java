package Kyber.Algorithm;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class KyberKeyPairGenerator
{
    public KeyPair generateKeys512(SecureRandom rand) throws Exception
    {
        int paramsK = 2;
        KeyPair indcpaPKI = this.generateKyberKeys(paramsK);
        byte[] packedPublicKey = indcpaPKI.getPublicKey();
        byte[] packedPrivateKey = indcpaPKI.getPrivateKey();
        byte[] privateKeyFixedLength = new byte[KyberParams.Kyber512SKBytes];
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        byte[] encodedHash = md.digest(packedPublicKey);
        byte[] pkh = new byte[encodedHash.length];
        System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.length);
        byte[] rnd = new byte[KyberParams.paramsSymBytes];
        rand.nextBytes(rnd);
        int offsetEnd = packedPrivateKey.length;
        System.arraycopy(packedPrivateKey, 0, privateKeyFixedLength, 0, offsetEnd);
        System.arraycopy(packedPublicKey, 0, privateKeyFixedLength, offsetEnd, packedPublicKey.length);
        offsetEnd = offsetEnd + packedPublicKey.length;
        System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.length);
        offsetEnd += pkh.length;
        System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.length);
        return new KeyPair(privateKeyFixedLength, packedPublicKey);
    }

    public KeyPair generateKeys768(SecureRandom rand) throws Exception
    {
        int paramsK = 3;
        KeyPair indcpaPKI = this.generateKyberKeys(paramsK);
        byte[] packedPrivateKey = indcpaPKI.getPrivateKey();
        byte[] packedPublicKey = indcpaPKI.getPublicKey();
        byte[] privateKeyFixedLength = new byte[KyberParams.Kyber768SKBytes];
        MessageDigest md = MessageDigest.getInstance("SHA3-256");

        byte[] encodedHash = md.digest(packedPublicKey);
        byte[] pkh = new byte[encodedHash.length];
        System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.length);
        byte[] rnd = new byte[KyberParams.paramsSymBytes];
        rand.nextBytes(rnd);

        int offsetEnd = packedPrivateKey.length;
        System.arraycopy(packedPrivateKey, 0, privateKeyFixedLength, 0, offsetEnd);
        System.arraycopy(packedPublicKey, 0, privateKeyFixedLength, offsetEnd, packedPublicKey.length);
        offsetEnd = offsetEnd + packedPublicKey.length;

        System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.length);
        offsetEnd += pkh.length;
        System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.length);
        return new KeyPair(privateKeyFixedLength, packedPublicKey);
    }

    public KeyPair generateKeys1024(SecureRandom rand) throws Exception
    {
        int paramsK = 4;
        KeyPair indcpaPKI = this.generateKyberKeys(paramsK);
        byte[] packedPrivateKey = indcpaPKI.getPrivateKey();
        byte[] packedPublicKey = indcpaPKI.getPublicKey();
        byte[] privateKeyFixedLength = new byte[KyberParams.Kyber1024SKBytes];
        MessageDigest md = MessageDigest.getInstance("SHA3-256");

        byte[] encodedHash = md.digest(packedPublicKey);
        byte[] pkh = new byte[encodedHash.length];
        System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.length);
        byte[] rnd = new byte[KyberParams.paramsSymBytes];
        rand.nextBytes(rnd);

        int offsetEnd = packedPrivateKey.length;
        System.arraycopy(packedPrivateKey, 0, privateKeyFixedLength, 0, offsetEnd);
        System.arraycopy(packedPublicKey, 0, privateKeyFixedLength, offsetEnd, packedPublicKey.length);
        offsetEnd = offsetEnd + packedPublicKey.length;

        System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.length);
        offsetEnd += pkh.length;
        System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.length);
        return new KeyPair(privateKeyFixedLength, packedPublicKey);
    }

    public KeyPair generateKyberKeys(int paramsK) throws Exception
    {
        short[][] skpv = Poly.generateNewPolyVector(paramsK);
        short[][] pkpv = Poly.generateNewPolyVector(paramsK);
        short[][] e = Poly.generateNewPolyVector(paramsK);
        byte[] publicSeed = new byte[KyberParams.paramsSymBytes];
        byte[] noiseSeed = new byte[KyberParams.paramsSymBytes];

        MessageDigest h = MessageDigest.getInstance("SHA3-512");
        SecureRandom sr = SecureRandom.getInstanceStrong();
        sr.nextBytes(publicSeed);
        byte[] fullSeed = h.digest(publicSeed);

        System.arraycopy(fullSeed, 0, publicSeed, 0, KyberParams.paramsSymBytes);
        System.arraycopy(fullSeed, KyberParams.paramsSymBytes, noiseSeed, 0, KyberParams.paramsSymBytes);
        short[][][] a = generateMatrix(publicSeed, false, paramsK);
        byte nonce = (byte) 0;
        for (int i = 0; i < paramsK; i++) {
            skpv[i] = Poly.getNoisePoly(noiseSeed, nonce, paramsK);
            nonce = (byte) (nonce + (byte) 1);
        }
        for (int i = 0; i < paramsK; i++) {
            e[i] = Poly.getNoisePoly(noiseSeed, nonce, paramsK);
            nonce = (byte) (nonce + (byte) 1);
        }
        skpv = Poly.polyVectorNTT(skpv, paramsK);
        skpv = Poly.polyVectorReduce(skpv, paramsK);
        e = Poly.polyVectorNTT(e, paramsK);
        for (int i = 0; i < paramsK; i++) {
            short[] temp = Poly.polyVectorPointWiseAccMont(a[i], skpv, paramsK);
            pkpv[i] = Poly.polyToMont(temp);
        }
        pkpv = Poly.polyVectorAdd(pkpv, e, paramsK);
        pkpv = Poly.polyVectorReduce(pkpv, paramsK);
        return new KeyPair(packPrivateKey(skpv, paramsK), packPublicKey(pkpv, publicSeed, paramsK));
    }

    public void generateUniform(KyberUniformRandom uniformRandom, byte[] buf, int bufl, int l) {
        short[] uniformR = new short[KyberParams.paramsPolyBytes];
        int d1;
        int d2;
        int uniformI = 0; // Always start at 0
        int j = 0;
        while ((uniformI < l) && ((j + 3) <= bufl)) {
            d1 = (int) (((((int) (buf[j] & 0xFF)) >> 0) | (((int) (buf[j + 1] & 0xFF)) << 8)) & 0xFFF);
            d2 = (int) (((((int) (buf[j + 1] & 0xFF)) >> 4) | (((int) (buf[j + 2] & 0xFF)) << 4)) & 0xFFF);
            j = j + 3;
            if (d1 < (int) KyberParams.paramsQ) {
                uniformR[uniformI] = (short) d1;
                uniformI++;
            }
            if (uniformI < l && d2 < (int) KyberParams.paramsQ) {
                uniformR[uniformI] = (short) d2;
                uniformI++;
            }
        }
        uniformRandom.setUniformI(uniformI);
        uniformRandom.setUniformR(uniformR);
    }

    public short[][][] generateMatrix(byte[] seed, boolean transposed, int paramsK) {
        short[][][] r = new short[paramsK][paramsK][KyberParams.paramsPolyBytes];
        byte[] buf = new byte[672];
        KyberUniformRandom uniformRandom = new KyberUniformRandom();
        KeccakSponge xof = new Shake128();
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.generateNewPolyVector(paramsK);
            for (int j = 0; j < paramsK; j++) {
                xof.reset();
                xof.getAbsorbStream().write(seed);
                byte[] ij = new byte[2];
                if (transposed) {
                    ij[0] = (byte) i;
                    ij[1] = (byte) j;
                } else {
                    ij[0] = (byte) j;
                    ij[1] = (byte) i;
                }
                xof.getAbsorbStream().write(ij);
                xof.getSqueezeStream().read(buf);
                generateUniform(uniformRandom, Arrays.copyOfRange(buf, 0, 504), 504, KyberParams.paramsN);
                int ui = uniformRandom.getUniformI();
                r[i][j] = uniformRandom.getUniformR();
                while (ui < KyberParams.paramsN) {
                    generateUniform(uniformRandom, Arrays.copyOfRange(buf, 504, 672), 168, KyberParams.paramsN - ui);
                    int ctrn = uniformRandom.getUniformI();
                    short[] missing = uniformRandom.getUniformR();
                    for (int k = ui; k < KyberParams.paramsN; k++) {
                        r[i][j][k] = missing[k - ui];
                    }
                    ui = ui + ctrn;
                }
            }
        }
        return r;
    }

    public byte[] packPrivateKey(short[][] privateKey, int paramsK) {
        byte[] packedPrivateKey = Poly.polyVectorToBytes(privateKey, paramsK);
        return packedPrivateKey;
    }

    public byte[] packPublicKey(short[][] publicKey, byte[] seed, int paramsK)
    {
        byte[] initialArray = Poly.polyVectorToBytes(publicKey, paramsK);
        switch (paramsK)
        {
            case 2:
                byte[] packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
                return packedPublicKey;
            case 3:
                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK768];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
                return packedPublicKey;
            default:
                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
                return packedPublicKey;
        }
    }
}