package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.JCSystem;
import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Implementation.SmartCard.dummy.RandomData;
import Kyber.KyberMain;
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
        //Create keccak instance so object is created, reserving EEPROM at startup rather than runtime
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.poly = Poly.getInstance();

        //Array sizes initialized only once and at highest Kyber settings so the "init" function can set the Kyber mode
        privateKey = new byte[(short)3168];
        publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
        this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK1024];
        this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        this.indcpaPrivateKey = new byte[KyberParams.paramsIndcpaSecretKeyBytesK1024];
        this.encapsulation = new byte[1568];
        this.privateKeyBytes = KyberParams.Kyber1024SKBytes;
        vc = new byte[(short)(1568 - KyberParams.paramsPolyvecCompressedBytesK1024)];
        EEPROM384S_X_PARAMS_K_1 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_2 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_3 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_4 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_X_PARAMS_K_1 = new short[(short)(384*4*4)];
        EEPROM384B_X_PARAMS_K_1 = new byte[(short)(384*4)];
        this.publicKeyPolyvec = new short[(short)(384*4)];

        EEPROM384_1 = new short[384];
        EEPROM384_2 = new short[384];
        EEPROM32B_1 = new byte[32];
        EEPROM32B_2 = new byte[32];
        EEPROM672B_1 = new byte[672];
        EEPROM504B_1 = new byte[504];
        EEPROM768B_1 = new byte[768];
        EEPROM1536B_1 = new byte[1536];
        EEPROM1568B_1 = new byte[1568];
        RAM2B_1 = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        EEPROM34_1 = new byte[34];
        EEPROM64B_1 = new byte[64];
        EEPROM64B_2 = new byte[64];
        EEPROM256S_1 = new short[256];
        this.seed = new byte[32];
    }

    private static KyberAlgorithm kyber;

    private KyberAlgorithm init(byte paramsK)
    {
        this.paramsK = paramsK;
        switch (paramsK)
        {
            case 2:
                privateKeyLength = 1632;
                publicKeyLength = KyberParams.paramsIndcpaPublicKeyBytesK512;
                vCompressLength = KyberParams.paramsPolyCompressedBytesK768;//yes 768 intended
                bCompressLength = KyberParams.paramsPolyvecCompressedBytesK512;
                indcpaPrivateKeyLength = KyberParams.paramsIndcpaSecretKeyBytesK512;
                privateKeyBytes = KyberParams.Kyber512SKBytes;
                break;
            case 3:
                privateKeyLength = 2400;
                publicKeyLength = KyberParams.paramsIndcpaPublicKeyBytesK768;
                vCompressLength = KyberParams.paramsPolyCompressedBytesK768;
                bCompressLength = KyberParams.paramsPolyvecCompressedBytesK768;
                indcpaPrivateKeyLength = KyberParams.paramsIndcpaSecretKeyBytesK768;
                privateKeyBytes = KyberParams.Kyber768SKBytes;
                break;
            default:
                privateKeyLength = 3168;
                publicKeyLength = KyberParams.paramsIndcpaPublicKeyBytesK1024;
                vCompressLength = KyberParams.paramsPolyCompressedBytesK1024;
                bCompressLength = KyberParams.paramsPolyvecCompressedBytesK1024;
                indcpaPrivateKeyLength = KyberParams.paramsIndcpaSecretKeyBytesK1024;
                privateKeyBytes = KyberParams.Kyber1024SKBytes;
                break;
        }
        encapsulationLength = (short)(bCompressLength + vCompressLength);
        vcLength = (short)(encapsulationLength - bCompressLength);
        return this;
    }

    public static KyberAlgorithm getInstance(byte paramsK)
    {
        if (kyber == null) kyber = new KyberAlgorithm(paramsK);
        return kyber.init(paramsK);
    }

    private byte paramsK;
    private Keccak keccak;
    private Poly poly;

    //Conditional arrays based on paramsK
    public byte[] privateKey;
    public short privateKeyLength;
    public byte[] publicKey;
    public short publicKeyLength;

    byte[] vCompress;//packCiphertext
    short vCompressLength;
    byte[] bCompress;//packCiphertext
    short bCompressLength;
    byte[] vc;
    short vcLength;
    byte[] indcpaPrivateKey;
    short indcpaPrivateKeyLength;
    short privateKeyBytes;
    public byte[] encapsulation;
    short encapsulationLength;


    short[] EEPROM384S_X_PARAMS_K_X_PARAMS_K_1;
    byte[] EEPROM384B_X_PARAMS_K_1;
    short[] EEPROM384S_X_PARAMS_K_1;
    short[] EEPROM384S_X_PARAMS_K_2;
    short[] EEPROM384S_X_PARAMS_K_3;
    short[] EEPROM384S_X_PARAMS_K_4;

    byte[] RAM2B_1;
    byte[] EEPROM34_1;
    byte[] EEPROM32B_1;
    byte[] EEPROM32B_2;
    byte[] EEPROM64B_1;
    byte[] EEPROM64B_2;
    short[] EEPROM256S_1;
    byte[] EEPROM672B_1;
    byte[] EEPROM768B_1;
    byte[] EEPROM1536B_1;
    byte[] EEPROM1568B_1;
    byte[] EEPROM504B_1;
    short[] EEPROM384_1;
    short[] EEPROM384_2;

    private short uniformI = 0;
    public byte[] secretKey;
    public byte[] plain;
    private short[] publicKeyPolyvec;
    private byte[] seed;
    
    //phase 2, opt ok
    public void encapsulate() throws Exception
    {
        //variant = EEPROM32B_1
        //buf = EEPROM32B_2
        //buf2 = EEPROM32B_1 (when variant no more used)
        //subKr = EEPROM32B_1 when buf2 no more used
        //krc = EEPROM32B_1 when subKir is no more used
        //sharedSecret = EEPROM32B_1 (when krc no more used)
        //buf3 = EEPROM64B_1
        //kr = EEPROM64B_2
        //newKr = EEPROM64B_1 when buf3 is no more used

        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        if (KyberMain.random) random.nextBytes(EEPROM32B_1, (short)0, (short)32);
        else for (byte i = 0; i < EEPROM32B_1.length; i++){EEPROM32B_1[i] = 0x00;}
        random.close();
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.keccak.doFinal(EEPROM32B_1, EEPROM32B_2);
        this.keccak.doFinal(this.publicKey, publicKeyLength, EEPROM32B_1);
        Util.arrayCopyNonAtomic(EEPROM32B_2, (short)0, EEPROM64B_1, (short)0, (short)EEPROM32B_2.length);
        Util.arrayCopyNonAtomic(EEPROM32B_1, (short)0, EEPROM64B_1, (short)EEPROM32B_2.length, (short)EEPROM32B_1.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        this.keccak.doFinal(EEPROM64B_1, EEPROM64B_2);
        Util.arrayCopyNonAtomic(EEPROM64B_2, KyberParams.paramsSymBytes, EEPROM32B_1, (short)0, (short)EEPROM32B_1.length);
        this.encrypt(EEPROM32B_2, this.publicKey, EEPROM32B_1);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.keccak.doFinal(this.encapsulation, encapsulationLength, EEPROM32B_1);
        Util.arrayCopyNonAtomic(EEPROM64B_2, (short)0, EEPROM64B_1, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(EEPROM32B_1, (short)0, EEPROM64B_1, KyberParams.paramsSymBytes, (short)EEPROM32B_1.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        this.keccak.setShakeDigestLength((short)32);
        this.keccak.doFinal(EEPROM64B_1, EEPROM32B_1);
        this.secretKey = EEPROM32B_1;
    }

    //phase 3, smart card ok, opt ok
    public void decapsulate() throws Exception
    {
        //newBuf = EEPROM64B_2
        //kr = EEPROM64B_1
        //subKr = EEPROM32B_1
        //krh = EEPROM32B_1
        //sharedSecretFixedLength = EEPROM32B_1
        //plain = EEPROM32B_2
        //tempBuf = EEPROM64B_2
        //return array = EEPROM1568B_1

        Util.arrayCopyNonAtomic(this.privateKey, (short)0, indcpaPrivateKey, (short)0, indcpaPrivateKeyLength);
        Util.arrayCopyNonAtomic(this.privateKey, indcpaPrivateKeyLength, publicKey, (short)0, publicKeyLength);
        this.decrypt(this.encapsulation, indcpaPrivateKey, EEPROM32B_2);//begin EEPROM32B_2
        short ski = (short)(privateKeyBytes - (2 * KyberParams.paramsSymBytes));
        Util.arrayCopyNonAtomic(EEPROM32B_2, (short)0, EEPROM64B_2, (short)0, (short)32);//begin EEPROM64B_2
        Util.arrayCopyNonAtomic(this.privateKey, ski, EEPROM64B_2, (short)32, KyberParams.paramsSymBytes);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        this.keccak.doFinal(EEPROM64B_2, EEPROM64B_1);//end EEPROM64B_2, begin EEPROM64B_1
        Util.arrayCopyNonAtomic(EEPROM64B_1, KyberParams.paramsSymBytes, EEPROM32B_1, (short)0, (short)32);//begin EEPROM32B_1
        Util.arrayCopyNonAtomic(this.encapsulation, (short)0, EEPROM1568B_1, (short)0, encapsulationLength);
        this.encrypt(EEPROM32B_2, publicKey, EEPROM32B_1);//end EEPROM32B_1
        byte fail = this.constantTimeCompare(this.encapsulation, EEPROM1568B_1, encapsulationLength);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.keccak.doFinal(this.encapsulation, encapsulationLength, EEPROM32B_1);//begin EEPROM32B_1
        short index = (short)(privateKeyBytes - KyberParams.paramsSymBytes);
        for (byte i = 0; i < KyberParams.paramsSymBytes; i++)
        {
            byte privateKeyIndex = (byte)(this.privateKey[index] & (byte)0xFF);
            byte krIndex = (byte)(EEPROM64B_1[i] & (byte)0xFF);
            EEPROM64B_1[i] = (byte)(krIndex ^ (byte)(fail & (byte)0xFF & (byte)(privateKeyIndex ^ krIndex)));
            index += 1;
        }
        Util.arrayCopyNonAtomic(EEPROM64B_1, (short)0, EEPROM64B_2, (short)0, KyberParams.paramsSymBytes);//end EEPROM64B_1, begin EEPROM64B_2
        Util.arrayCopyNonAtomic(EEPROM32B_1, (short)0, EEPROM64B_2, KyberParams.paramsSymBytes, (short)EEPROM32B_1.length);//end EEPROM32B_1
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        this.keccak.setShakeDigestLength((short)32);
        this.keccak.doFinal(EEPROM64B_2, EEPROM32B_1);//end EEPROM64B_2, begin EEPROM32B_1
        this.plain = EEPROM32B_2;//end EEPROM32B_2
        this.secretKey = EEPROM32B_1; //end EEPROM32B_1
    }

    //phase 3, smart card ok, opt ok
    public void decrypt(byte[] packedCipherText, byte[] privateKey, byte[] msg)
    {
        //cannot use EEPROM32B_2

        //unpackedPrivateKey = EEPROM384S_X_PARAMS_K_1
        //mp = EEPROM384_1

        this.unpackCiphertext(packedCipherText, this.paramsK);//begin EEPROM384S_X_PARAMS_K_2, begin EEPROM384_2
        this.unpackPrivateKey(privateKey, this.paramsK, EEPROM384S_X_PARAMS_K_1);//begin EEPROM384S_X_PARAMS_K_1
        Poly.getInstance().polyVectorNTT(EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorPointWiseAccMont(EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, this.paramsK, EEPROM384_1);//end EEPROM384S_X_PARAMS_K_1, begin EEPROM384_1, end EEPROM384S_X_PARAMS_K_2
        Poly.getInstance().polyInvNTTMont(EEPROM384_1);
        Poly.getInstance().polySub(EEPROM384_2, EEPROM384_1);//end EEPROM384_1
        Poly.getInstance().polyReduce(EEPROM384_2);
        Poly.getInstance().polyToMsg(EEPROM384_2, msg);//end EEPROM384_2
    }

    //phase 2 smart card ok, opt ok
    public void encrypt(byte[] m, byte[] publicKey, byte[] coins)
    {
        //cannot use EEPROM64B_1
        //cannot use EEPROM64B_2
        //cannot use EEPROM384_1
        //cannot use EEPROM384S_X_PARAMS_K_1

        //m = EEPROM32B_2
        //coins = EEPROM32B_1
        //EEPROM384S_X_PARAMS_K_2 = sp
        //EEPROM384S_X_PARAMS_K_3 = ep
        //EEPROM384S_X_PARAMS_K_4 = bp
        //EEPROM384_2 = epp
        //at = EEPROM384S_X_PARAMS_K_X_PARAMS_K_1
        //k = EEPROM256S_1

        Poly.getInstance().polyFromData(m, EEPROM256S_1);
        this.unpackPublicKey(publicKey, paramsK);
        this.generateMatrix(this.seed, true, EEPROM384S_X_PARAMS_K_X_PARAMS_K_1);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(coins, i, paramsK, EEPROM384_2);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_2, (short)0, EEPROM384S_X_PARAMS_K_2,(short)(i*384),(short)384);
            Poly.getInstance().getNoisePoly(coins, (byte)(i + paramsK), (byte)3,EEPROM384_2);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_2, (short)0, EEPROM384S_X_PARAMS_K_3,(short)(i*384),(short)384);
        }
        Poly.getInstance().getNoisePoly(coins, (byte)(paramsK * 2), (byte)3, EEPROM384_2);
        Poly.getInstance().polyVectorNTT(EEPROM384S_X_PARAMS_K_2, paramsK);
        Poly.getInstance().polyVectorReduce(EEPROM384S_X_PARAMS_K_2,paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384S_X_PARAMS_K_X_PARAMS_K_1, (short)(i*paramsK*384), this.EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*paramsK));
            Poly.getInstance().polyVectorPointWiseAccMont(this.EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, paramsK, EEPROM384_1);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_1, (short)0,EEPROM384S_X_PARAMS_K_4,(short)(i*384),(short)384);
        }
        Poly.getInstance().polyVectorPointWiseAccMont(this.publicKeyPolyvec, EEPROM384S_X_PARAMS_K_2, paramsK, EEPROM384_1);
        Poly.getInstance().polyVectorInvNTTMont(EEPROM384S_X_PARAMS_K_4, paramsK);
        Poly.getInstance().polyInvNTTMont(EEPROM384_1);
        Poly.getInstance().polyVectorAdd(EEPROM384S_X_PARAMS_K_4, EEPROM384S_X_PARAMS_K_3, paramsK);
        Poly.getInstance().polyAdd(EEPROM384_1, EEPROM384_2);
        Poly.getInstance().polyAdd(EEPROM384_1, EEPROM256S_1);
        Poly.getInstance().polyVectorReduce(EEPROM384S_X_PARAMS_K_4, paramsK);
        Poly.getInstance().polyReduce(EEPROM384_1);
        this.packCiphertext(EEPROM384S_X_PARAMS_K_4, EEPROM384_1, paramsK);
    }

    //phase 1 smart card ok, opt ok
    //r = array 1 || array 1.1 || array 1.2 || array 2 || array 2.1 || array 2.2 || array 3 || array 3.1 ...
    public void generateMatrix(byte[] seed, boolean transposed, short[] result)
    {
        //seed = EEPROM32B_1
        //result = EEPROM384S_X_PARAMS_K_X_PARAMS_K_1, 2*2*384 = 1536
        //EEPROM672B_1 = buf
        //EEPROM504B_1 = bufCopy
        //RAM2B_1 = ij
        //EEPROM34_1 = seedAndij
        //EEPROM384_1 = uniformR

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
                Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384_1, (short)0, result, (short)(((i*this.paramsK)+j)*384), (short)384);
                while (ui < KyberParams.paramsN)
                {
                    Util.arrayCopyNonAtomic(this.EEPROM672B_1,(short)504, this.EEPROM504B_1,(short)0, (short)168);
                    this.generateUniform(this.EEPROM504B_1, (short)168, (short)(KyberParams.paramsN - ui));
                    short ctrn = this.uniformI;
                    for (short k = ui; k < KyberParams.paramsN; k++)
                    {
                        result[(short)(((i * this.paramsK + j) * 384) + k)] = this.EEPROM384_1[(short)(k - ui)];
                    }
                    ui += ctrn;
                }
            }
        }
    }

    //phase 3, smart card ok, need opt
    public byte constantTimeCompare(byte[] x, byte[] y, short length)
    {
        if (x.length != y.length) return (byte)1;
        byte v = 0;
        for (short i = 0; i < length; i++)
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
//                emptyBytes[i] = (byte)0;
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
        this.keccak.doFinal(this.publicKey, publicKeyLength, EEPROM32B_1);
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        if (KyberMain.random) random.nextBytes(this.EEPROM32B_2, (short)0, (short)32);
        else for (byte i = 0; i < EEPROM32B_2.length; i++){EEPROM32B_2[i] = (byte)0x00;}
        random.close();
        short offsetEnd = (short)(this.paramsK * KyberParams.paramsPolyBytes);
        Util.arrayCopyNonAtomic(this.publicKey, (short)0, this.privateKey, offsetEnd, this.publicKeyLength);
        offsetEnd = (short)(offsetEnd + this.publicKeyLength);
        Util.arrayCopyNonAtomic(this.EEPROM32B_1, (short)0, this.privateKey, offsetEnd, (short)this.EEPROM32B_1.length);
        offsetEnd += (short)this.EEPROM32B_1.length;
        Util.arrayCopyNonAtomic(this.EEPROM32B_2, (short)0, this.privateKey, offsetEnd, (short)this.EEPROM32B_2.length);
        //priv = priv || pub || pkh (pub hash) || rnd
    }

    //phase 1
    //smart card ok, opt ok
    public void generateKyberKeys() throws Exception
    {
        //EEPROM384S_X_PARAMS_K_X_PARAMS_K_1 = a
        //EEPROM384S_X_PARAMS_K_1 = sub 384 of a
        //EEPROM384S_X_PARAMS_K_2 = skpv
        //EEPROM384S_X_PARAMS_K_3 = pkpv
        //EEPROM384S_X_PARAMS_K_4 = e
        //EEPROM32B_1 = publicSeed
        //EEPROM32B_2 = noiseSeed
        //EEPROM384B_X_PARAMS_K_1 = fullSeed

        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        if (KyberMain.random) random.nextBytes(this.EEPROM32B_1, (short)0, (short)32);
        else for (byte i = 0; i < EEPROM32B_1.length; i++){EEPROM32B_1[i] = (byte)0x00;}
        random.close();
        this.keccak.doFinal(this.EEPROM32B_1, this.EEPROM384B_X_PARAMS_K_1);
        Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K_1, (short)0, this.EEPROM32B_1, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K_1, KyberParams.paramsSymBytes, this.EEPROM32B_2, (short)0, KyberParams.paramsSymBytes);
        this.generateMatrix(this.EEPROM32B_1, false, this.EEPROM384S_X_PARAMS_K_X_PARAMS_K_1);
        byte nonce = (byte)0;
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(this.EEPROM32B_2, nonce, this.paramsK, this.EEPROM384_1);
            Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384_1, (short)0, this.EEPROM384S_X_PARAMS_K_2, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(this.EEPROM32B_2, nonce, this.paramsK, this.EEPROM384_1);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_1, (short)0, this.EEPROM384S_X_PARAMS_K_4, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        Poly.getInstance().polyVectorNTT(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorReduce(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorNTT(this.EEPROM384S_X_PARAMS_K_4, this.paramsK);
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384S_X_PARAMS_K_X_PARAMS_K_1, (short)(i*this.paramsK*384), this.EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*this.paramsK));
            Poly.getInstance().polyVectorPointWiseAccMont(this.EEPROM384S_X_PARAMS_K_1, this.EEPROM384S_X_PARAMS_K_2, this.paramsK, this.EEPROM384_1);
            Poly.getInstance().polyToMont(this.EEPROM384_1);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_1, (short)0, this.EEPROM384S_X_PARAMS_K_3, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
        }
        Poly.getInstance().polyVectorAdd(this.EEPROM384S_X_PARAMS_K_3, this.EEPROM384S_X_PARAMS_K_4, this.paramsK);
        Poly.getInstance().polyVectorReduce(this.EEPROM384S_X_PARAMS_K_3, this.paramsK);
        this.packPrivateKey(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        this.packPublicKey(this.EEPROM384S_X_PARAMS_K_3, this.EEPROM32B_1, this.paramsK);
    }

    //phase 1 smart card ok, opt ok
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
                this.EEPROM384_1[this.uniformI] = d1;
                this.uniformI++;
            }
            if (this.uniformI < l && d2 < KyberParams.paramsQ)
            {
                this.EEPROM384_1[this.uniformI] = d2;
                this.uniformI++;
            }
        }
    }

    //phase 1
    //smart card ok, opt ok
    public void packPrivateKey(short[] privateKey, byte paramsK)
    {
        Poly.getInstance().polyVectorToBytes(privateKey, paramsK, this.privateKey);
    }

    //phase 1
    //smart card ok, opt ok
    public void packPublicKey(short[] publicKey, byte[] seed, byte paramsK)
    {
        //initialArray = EEPROM384B_X_PARAMS_K_1
        //packedPublicKey = this.publicKey

        Poly.getInstance().polyVectorToBytes(publicKey, paramsK, this.EEPROM384B_X_PARAMS_K_1);
        Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K_1, (short)0, this.publicKey, (short)0, (short)(384*paramsK));
        Util.arrayCopyNonAtomic(seed, (short)0, this.publicKey, (short)(384*paramsK), (short)seed.length);
    }

    //phase 2, smart card op, opt ok
    public void packCiphertext(short[] b, short[] v, byte paramsK)
    {
        Poly.getInstance().compressPolyVector(b, paramsK, this.bCompress);
        Poly.getInstance().compressPoly(v, paramsK, this.vCompress);
        Util.arrayCopyNonAtomic(this.bCompress, (short)0, encapsulation, (short)0, bCompressLength);
        Util.arrayCopyNonAtomic(this.vCompress, (short)0, encapsulation, bCompressLength, vCompressLength);
    }

    //phase 3, smart card ok, opt ok
    public void unpackCiphertext(byte[] c, byte paramsK)
    {
        //bp = EEPROM384S_X_PARAMS_K_2
        Util.arrayCopyNonAtomic(c, (short)0, bCompress, (short)0, bCompressLength);
        Util.arrayCopyNonAtomic(c, bCompressLength, vc, (short)0, vcLength);
        Poly.getInstance().decompressPolyVector(bCompress, paramsK, EEPROM384S_X_PARAMS_K_2);
        Poly.getInstance().decompressPoly(vc, paramsK, EEPROM384_2);
    }

    //phase 3, smart card ok, opt ok
    public void unpackPrivateKey(byte[] packedPrivateKey, byte paramsK, short[] r)
    {
        Poly.getInstance().polyVectorFromBytes(packedPrivateKey, paramsK, r);
    }

    //phase 2 smart card ok, opt ok
    public void unpackPublicKey(byte[] packedPublicKey, byte paramsK)
    {
        //r = this.publicKeyPolyvec
        //partlyPublicKey = EEPROM1536B_1 based on highest paramsK 4

        switch (paramsK)
        {
            case 2:
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM1536B_1, (short)0, KyberParams.paramsPolyvecBytesK512);
                Poly.getInstance().polyVectorFromBytes(EEPROM1536B_1, paramsK, this.publicKeyPolyvec);
                Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK512, this.seed, (short)0, (short)32);
                break;
            case 3:
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM1536B_1, (short)0, KyberParams.paramsPolyvecBytesK768);
                Poly.getInstance().polyVectorFromBytes(EEPROM1536B_1, paramsK, this.publicKeyPolyvec);
                Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK768, this.seed, (short)0, (short)32);
                break;
            default:
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM1536B_1, (short)0, KyberParams.paramsPolyvecBytesK1024);
                Poly.getInstance().polyVectorFromBytes(EEPROM1536B_1, paramsK, this.publicKeyPolyvec);
                Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK1024, this.seed, (short)0, (short)32);
                break;
        }
    }
}