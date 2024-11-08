package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.JCSystem;
import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Implementation.SmartCard.dummy.RandomData;
import Kyber.Models.*;

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
        switch (paramsK)
        {
            case 2:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK768];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
            case 3:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK768];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
                break;
            default:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK1024];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
                break;
        }
        this.returnArray = new byte[(short)(this.bCompress.length + this.vCompress.length)];
        EEPROM384S_X_PARAMS_K_1 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_2 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_3 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_4 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_X_PARAMS_K = new short[(short)(384*paramsK*paramsK)];
        EEPROM384B_X_PARAMS_K = new byte[(short)(384*paramsK)];
        EEPROM384 = new short[384];
        EEPROM384_2 = new short[384];
        EEPROM32B_1 = new byte[32];
        EEPROM32B_2 = new byte[32];
        EEPROM672B_1 = new byte[672];
        EEPROM504B_1 = new byte[504];
        RAM2B_1 = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        EEPROM34_1 = new byte[34];
    }

    private static KyberAlgorithm kyber;

    public static KyberAlgorithm getInstance(byte paramsK)
    {
        if (kyber == null) kyber = new KyberAlgorithm(paramsK);
        return kyber;
    }

    private byte paramsK;
    private Keccak keccak;
    private final KeyPair keyPair;

    //Conditional arrays based on paramsK
    byte[] vCompress;//packCiphertext
    byte[] bCompress;//packCiphertext
    byte[] returnArray;//packCiphertext
    short[] EEPROM384S_X_PARAMS_K_X_PARAMS_K;
    byte[] EEPROM384B_X_PARAMS_K;
    short[] EEPROM384S_X_PARAMS_K_1;
    short[] EEPROM384S_X_PARAMS_K_2;
    short[] EEPROM384S_X_PARAMS_K_3;
    short[] EEPROM384S_X_PARAMS_K_4;

    byte[] RAM2B_1;
    byte[] EEPROM34_1;
    byte[] EEPROM32B_1;
    byte[] EEPROM32B_2;
    byte[] EEPROM672B_1;
    byte[] EEPROM504B_1;
    short[] EEPROM384;
    short[] EEPROM384_2;

    private short uniformI = 0;

    public byte[] encapsulation;
    public byte[] secretKey;
    public byte[] plain;

    private short[] publicKeyPolyvec;
    private byte[] seed;

    short[] bp;
    short[] v;
    
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
        this.encrypt(buf1, publicKey, subKr);
        byte[] ciphertext = this.returnArray;//todo ned opt
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krc = new byte[32];
        this.keccak.doFinal(ciphertext, krc);
        byte[] newKr = new byte[(short)(KyberParams.paramsSymBytes + krc.length)];
        Util.arrayCopyNonAtomic(kr, (short)0, newKr, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(krc, (short)0, newKr, KyberParams.paramsSymBytes, (short)krc.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        this.keccak.setShakeDigestLength((short)32);
        this.keccak.doFinal(newKr, sharedSecret);
        this.encapsulation = ciphertext;//dont do this, use it as reference
        this.secretKey = sharedSecret;//dont do this, use it as reference
    }

    //phase 3
    public void decapsulate(short secretKeyBytes, short publicKeyBytes, short privateKeyBytes) throws Exception
    {
        byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
        byte[] indcpaPrivateKey = new byte[secretKeyBytes];
        Util.arrayCopyNonAtomic(this.keyPair.privateKey, (short)0, indcpaPrivateKey, (short)0, (short)indcpaPrivateKey.length);
        byte[] publicKey = new byte[publicKeyBytes];
        Util.arrayCopyNonAtomic(this.keyPair.privateKey, secretKeyBytes, publicKey, (short)0, (short)publicKey.length);
        //buf renamed to plain
        byte[] plain = this.decrypt(this.encapsulation, indcpaPrivateKey);
        short ski = (short)(privateKeyBytes - (2 * KyberParams.paramsSymBytes));
        byte[] newBuf = new byte[(short)(plain.length + KyberParams.paramsSymBytes)];
        Util.arrayCopyNonAtomic(plain, (short)0, newBuf, (short)0, (short)plain.length);
        Util.arrayCopyNonAtomic(this.keyPair.privateKey, ski, newBuf, (short)plain.length, KyberParams.paramsSymBytes);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] kr = new byte[64];
        this.keccak.doFinal(newBuf, kr);
        byte[] subKr = new byte[(short)(kr.length - KyberParams.paramsSymBytes)];
        Util.arrayCopyNonAtomic(kr, KyberParams.paramsSymBytes, subKr, (short)0, (short)subKr.length);
        this.encrypt(plain, publicKey, subKr);
        byte[] cmp = this.returnArray;//todo need opt
        byte fail = this.constantTimeCompare(this.encapsulation, cmp);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        byte[] krh = new byte[32];
        this.keccak.doFinal(this.encapsulation, krh);
        short index = (short)(privateKeyBytes - KyberParams.paramsSymBytes);
        for (byte i = 0; i < KyberParams.paramsSymBytes; i++)
        {
            byte privateKeyIndex = (byte)(this.keyPair.privateKey[index] & (byte)0xFF);
            byte krIndex = (byte)(kr[i] & (byte)0xFF);
            kr[i] = (byte)(krIndex ^ (byte)(fail & (byte)0xFF & (byte)(privateKeyIndex ^ krIndex)));
            index += 1;
        }
        byte[] tempBuf = new byte[(short)(KyberParams.paramsSymBytes + krh.length)];
        Util.arrayCopyNonAtomic(kr, (short)0, tempBuf, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(krh, (short)0, tempBuf, KyberParams.paramsSymBytes, (short)krh.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        this.keccak.setShakeDigestLength((short)32);
        this.keccak.doFinal(tempBuf, sharedSecretFixedLength);
        this.plain = plain;
        this.secretKey = sharedSecretFixedLength;
    }

    //phase 3, smart card ok, need opt
    public byte[] decrypt(byte[] packedCipherText, byte[] privateKey)
    {
        this.unpackCiphertext(packedCipherText, this.paramsK);
        short[] unpackedPrivateKey = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
        this.unpackPrivateKey(privateKey, this.paramsK, unpackedPrivateKey);
        Poly.getInstance().polyVectorNTT(this.bp, this.paramsK);
        Poly.getInstance().polyVectorPointWiseAccMont(unpackedPrivateKey, this.bp, this.paramsK, EEPROM384);//EEPROM384 = mp
        Poly.getInstance().polyInvNTTMont(EEPROM384);
        Poly.getInstance().polySub(this.v, EEPROM384);
        Poly.getInstance().polyReduce(this.v);
        byte[] msg = new byte[KyberParams.paramsSymBytes];
        Poly.getInstance().polyToMsg(this.v, msg);
        return msg;
    }

    //phase 2 smart card ok
    public void encrypt(byte[] m, byte[] publicKey, byte[] coins)
    {
        short[] sp = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
        short[] ep = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
        short[] bp = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
        short[] k = new short[KyberParams.paramsN];
        Poly.getInstance().polyFromData(m, k);
        this.unpackPublicKey(publicKey, paramsK);
        byte[] partlySeed = new byte[KyberParams.paramsSymBytes];//Opt this away
        Util.arrayCopyNonAtomic(this.seed, (short)0, partlySeed, (short)0, KyberParams.paramsSymBytes);
        short[] at = new short[(short)(this.paramsK*this.paramsK*KyberParams.paramsPolyBytes)];
        this.generateMatrix(partlySeed, true, at);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(coins, i, paramsK, EEPROM384_2);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_2, (short)0, sp,(short)(i*384),(short)384);
            Poly.getInstance().getNoisePoly(coins, (byte)(i + paramsK), (byte)3,EEPROM384_2);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_2, (short)0, ep,(short)(i*384),(short)384);
        }
        Poly.getInstance().getNoisePoly(coins, (byte)(paramsK * 2), (byte)3, EEPROM384_2);
        Poly.getInstance().polyVectorNTT(sp, paramsK);
        Poly.getInstance().polyVectorReduce(sp,paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(at, (short)(i*paramsK*384), this.EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*paramsK));
            Poly.getInstance().polyVectorPointWiseAccMont(this.EEPROM384S_X_PARAMS_K_1, sp, paramsK, EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384, (short)0,bp,(short)(i*384),(short)384);
        }
        Poly.getInstance().polyVectorPointWiseAccMont(this.publicKeyPolyvec, sp, paramsK, EEPROM384);
        Poly.getInstance().polyVectorInvNTTMont(bp, paramsK);
        Poly.getInstance().polyInvNTTMont(EEPROM384);
        Poly.getInstance().polyVectorAdd(bp, ep, paramsK);
        Poly.getInstance().polyAdd(EEPROM384, EEPROM384_2);//EEPROM384_2 = epp
        Poly.getInstance().polyAdd(EEPROM384, k);
        Poly.getInstance().polyVectorReduce(bp, paramsK);
        Poly.getInstance().polyReduce(EEPROM384);
        this.packCiphertext(bp, EEPROM384, paramsK);
    }

    //phase 1 smart card ok, need optimization
    //r = array 1 || array 1.1 || array 1.2 || array 2 || array 2.1 || array 2.2 || array 3 || array 3.1 ...
    public void generateMatrix(byte[] seed, boolean transposed, short[] result)
    {
        //seed = EEPROM32B_1
        //result = EEPROM384S_X_PARAMS_K_X_PARAMS_K, 2*2*384 = 1536
        //EEPROM672B_1 = buf
        //EEPROM504B_1 = bufCopy
        //RAM2B_1 = ij
        //EEPROM34_1 = seedAndij
        //EEPROM384 = uniformR

        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_128);
        for (byte i = 0; i < this.paramsK; i++)
        {
            for (byte j = 0; j < this.paramsK; j++)
            {
                if (transposed)
                {
                    this.RAM2B_1[0] = i;
                    this.RAM2B_1[1] = j;
                }
                else
                {
                    this.RAM2B_1[0] = j;
                    this.RAM2B_1[1] = i;
                }
                Util.arrayCopyNonAtomic(seed, (short)0, this.EEPROM34_1, (short)0, (short)seed.length);
                Util.arrayCopyNonAtomic(this.RAM2B_1, (short)0, this.EEPROM34_1, (short)seed.length, (short)this.RAM2B_1.length);
                this.keccak.setShakeDigestLength((short)this.EEPROM672B_1.length);
                this.keccak.doFinal(this.EEPROM34_1, this.EEPROM672B_1);
                Util.arrayCopyNonAtomic(this.EEPROM672B_1,(short)0, this.EEPROM504B_1,(short)0, (short)504);
                this.generateUniform(this.EEPROM504B_1, (short)504, KyberParams.paramsN);
                short ui = this.uniformI;
                Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384, (short)0, result, (short)(((i*2)+j)*384), (short)384);
                while (ui < KyberParams.paramsN)
                {
                    Util.arrayCopyNonAtomic(this.EEPROM672B_1,(short)504, this.EEPROM504B_1,(short)0, (short)168);
                    this.generateUniform(this.EEPROM504B_1, (short)168, (short)(KyberParams.paramsN - ui));
                    short ctrn = this.uniformI;
                    for (short k = ui; k < KyberParams.paramsN; k++)
                    {
                        result[(short)(((i * 2 + j) * 384) + k)] = this.EEPROM384[(short)(k - ui)];
                    }
                    ui += ctrn;
                }
            }
        }
    }

    //phase 3, smart card ok, need opt
    public byte constantTimeCompare(byte[] x, byte[] y)
    {
        if (x.length != y.length) return (byte)1;
        byte v = 0;
        for (short i = 0; i < x.length; i++)
        {
            v = (byte)((v & 0xFF) | ((x[i] & 0xFF) ^ (y[i] & 0xFF)));
        }
        //Byte.compare(v, (byte)0) - returns always v since implementation of Byte.compare is x-y, where x = v and y = 0; v-0 = v
        return v;
    }

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

    //smart card ok, opt ok
    public void generateKeys() throws Exception
    {
        //EEPROM32B_1 = encodedHash and pkh
        //EEPROM32B_2 = rnd

        this.generateKyberKeys();
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.keccak.doFinal(this.keyPair.publicKey, EEPROM32B_1);
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        random.nextBytes(this.EEPROM32B_2, (short)0, (short)32);
        random.close();
        short offsetEnd = (short)(this.paramsK * KyberParams.paramsPolyBytes);
        Util.arrayCopyNonAtomic(this.keyPair.publicKey, (short)0, this.keyPair.privateKey, offsetEnd, (short)this.keyPair.publicKey.length);
        offsetEnd = (short)(offsetEnd + this.keyPair.publicKey.length);
        Util.arrayCopyNonAtomic(this.EEPROM32B_1, (short)0, this.keyPair.privateKey, offsetEnd, (short)this.EEPROM32B_1.length);
        offsetEnd += (short)this.EEPROM32B_1.length;
        Util.arrayCopyNonAtomic(this.EEPROM32B_2, (short)0, this.keyPair.privateKey, offsetEnd, (short)this.EEPROM32B_2.length);
        //priv = priv || pub || pkh (pub hash) || rnd
    }

    //phase 1
    //smart card ok, opt ok
    public void generateKyberKeys() throws Exception
    {
        //EEPROM384S_X_PARAMS_K_X_PARAMS_K = a
        //EEPROM384S_X_PARAMS_K_1 = sub 384 of a
        //EEPROM384S_X_PARAMS_K_2 = skpv
        //EEPROM384S_X_PARAMS_K_3 = pkpv
        //EEPROM384S_X_PARAMS_K_4 = e
        //EEPROM32B_1 = publicSeed
        //EEPROM32B_2 = noiseSeed
        //EEPROM384B_X_PARAMS_K = fullSeed

        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
//        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//        random.nextBytes(publicSeed, (short)0, (short)32);
//        random.close();
        this.keccak.doFinal(this.EEPROM32B_1, this.EEPROM384B_X_PARAMS_K);
        Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K, (short)0, this.EEPROM32B_1, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K, KyberParams.paramsSymBytes, this.EEPROM32B_2, (short)0, KyberParams.paramsSymBytes);
        this.generateMatrix(this.EEPROM32B_1, false, this.EEPROM384S_X_PARAMS_K_X_PARAMS_K);
        byte nonce = (byte)0;
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(this.EEPROM32B_2, nonce, this.paramsK, this.EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384, (short)0, this.EEPROM384S_X_PARAMS_K_2, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(this.EEPROM32B_2, nonce, this.paramsK, this.EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384, (short)0, this.EEPROM384S_X_PARAMS_K_4, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        Poly.getInstance().polyVectorNTT(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorReduce(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorNTT(this.EEPROM384S_X_PARAMS_K_4, this.paramsK);
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384S_X_PARAMS_K_X_PARAMS_K, (short)(i*this.paramsK*384), this.EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*this.paramsK));
            Poly.getInstance().polyVectorPointWiseAccMont(this.EEPROM384S_X_PARAMS_K_1, this.EEPROM384S_X_PARAMS_K_2, this.paramsK, this.EEPROM384);
            Poly.getInstance().polyToMont(this.EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384, (short)0, this.EEPROM384S_X_PARAMS_K_3, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
        }
        Poly.getInstance().polyVectorAdd(this.EEPROM384S_X_PARAMS_K_3, this.EEPROM384S_X_PARAMS_K_4, this.paramsK);
        Poly.getInstance().polyVectorReduce(this.EEPROM384S_X_PARAMS_K_3, this.paramsK);
        this.packPrivateKey(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        this.packPublicKey(this.EEPROM384S_X_PARAMS_K_3, this.EEPROM32B_1, this.paramsK);
    }

    //phase 1 smart card ok, need optimizing
    public void generateUniform(byte[] buf, short bufl, short l)
    {
        short d1;
        short d2;
        this.uniformI = 0; // Always start at 0
        short j = 0;
        while ((this.uniformI < l) && ((short)(j + 3) <= bufl))
        {
            d1 = (short)(((buf[j] & 0xFF) | ((buf[(short)(j + 1)] & 0xFF) << 8)) & 0xFFF);
            d2 = (short)((((buf[(short)(j + 1)] & 0xFF) >> 4) | ((buf[(short)(j + 2)] & 0xFF) << 4)) & 0xFFF);
            j+=3;
            if (d1 < KyberParams.paramsQ)
            {
                this.EEPROM384[this.uniformI] = d1;
                this.uniformI++;
            }
            if (this.uniformI < l && d2 < KyberParams.paramsQ)
            {
                this.EEPROM384[this.uniformI] = d2;
                this.uniformI++;
            }
        }
    }

    //phase 1
    //smart card ok, opt ok
    public void packPrivateKey(short[] privateKey, byte paramsK)
    {
        Poly.getInstance().polyVectorToBytes(privateKey, paramsK, this.keyPair.privateKey);
    }

    //phase 1
    //smart card ok, opt ok
    public void packPublicKey(short[] publicKey, byte[] seed, byte paramsK)
    {
        Poly.getInstance().polyVectorToBytes(publicKey, paramsK, this.EEPROM384B_X_PARAMS_K);
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K, (short)0, this.keyPair.publicKey, (short)0, (short)this.EEPROM384B_X_PARAMS_K.length);
            Util.arrayCopyNonAtomic(seed, (short)0, this.keyPair.publicKey, (short)this.EEPROM384B_X_PARAMS_K.length, (short)seed.length);
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

    //phase 2, smart card op, opt ok
    public void packCiphertext(short[] b, short[] v, byte paramsK)
    {
        Poly.getInstance().compressPolyVector(b, paramsK, this.bCompress);
        Poly.getInstance().compressPoly(v, paramsK, this.vCompress);
        Util.arrayCopyNonAtomic(this.bCompress, (short)0, this.returnArray, (short)0, (short)this.bCompress.length);
        Util.arrayCopyNonAtomic(this.vCompress, (short)0, this.returnArray, (short)this.bCompress.length, (short)this.vCompress.length);
    }

    //phase 3, smart card ok, need opt
    public void unpackCiphertext(byte[] c, byte paramsK)
    {
        byte[] bpc;
        byte[] vc;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
//            case 3:
//                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
//                break;
//            default:
//                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        }
        Util.arrayCopyNonAtomic(c, (short)0, bpc, (short)0, (short)bpc.length);
        vc = new byte[(short)(c.length - bpc.length)];
        Util.arrayCopyNonAtomic(c, (short)bpc.length, vc, (short)0, (short)vc.length);
        this.bp = Poly.getInstance().decompressPolyVector(bpc, paramsK);
        this.v = Poly.getInstance().decompressPoly(vc, paramsK);
    }

    //phase 3, smart card ok
    public void unpackPrivateKey(byte[] packedPrivateKey, byte paramsK, short[] r)
    {
        Poly.getInstance().polyVectorFromBytes(packedPrivateKey, paramsK, r);
    }

    //phase 2 smart card ok, check seed
    public void unpackPublicKey(byte[] packedPublicKey, byte paramsK)
    {
        short[] r = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];//todo
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
                byte[] partlyPublicKey = new byte[KyberParams.paramsPolyvecBytesK512];
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, partlyPublicKey, (short)0, KyberParams.paramsPolyvecBytesK512);
                Poly.getInstance().polyVectorFromBytes(partlyPublicKey, paramsK, r);
                this.publicKeyPolyvec = r;
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