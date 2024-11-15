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
        //Create keccak instance so object is created, reserving EEPROM at startup rather than runtime
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.paramsK = paramsK;
        this.keyPair = KeyPair.getInstance(paramsK);
        this.poly = Poly.getInstance();
        switch (paramsK)
        {
            case 2:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK768];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                this.indcpaPrivateKey = new byte[768];
                this.encapsulation = new byte[768];
                this.privateKeyBytes = KyberParams.Kyber512SKBytes;
                break;
            case 3:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK768];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
//                this.indcpaPrivateKey = new byte[768];//todo
                this.encapsulation = new byte[1088];//todo
                this.privateKeyBytes = KyberParams.Kyber768SKBytes;
                break;
            default:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK1024];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
//                this.indcpaPrivateKey = new byte[768];//todo
                this.encapsulation = new byte[1568];//todo
                this.privateKeyBytes = KyberParams.Kyber1024SKBytes;
                break;
        }
        this.returnArray = new byte[(short)(this.bCompress.length + this.vCompress.length)];
        vc = new byte[(short)(encapsulation.length - bCompress.length)];
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
        EEPROM768B_1 = new byte[768];
        RAM2B_1 = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        EEPROM34_1 = new byte[34];
        EEPROM64B_1 = new byte[64];
        EEPROM64B_2 = new byte[64];
        EEPROM256S_1 = new short[256];
        this.seed = new byte[32];
        this.publicKeyPolyvec = new short[(short)(384*paramsK)];
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
    private Poly poly;

    //Conditional arrays based on paramsK
    byte[] vCompress;//packCiphertext
    byte[] bCompress;//packCiphertext
    byte[] returnArray;//packCiphertext
    byte[] vc;
    byte[] indcpaPrivateKey;
    short privateKeyBytes;


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
    byte[] EEPROM64B_1;
    byte[] EEPROM64B_2;
    short[] EEPROM256S_1;
    byte[] EEPROM672B_1;
    byte[] EEPROM768B_1;
    byte[] EEPROM504B_1;
    short[] EEPROM384;
    short[] EEPROM384_2;

    private short uniformI = 0;
    public byte[] encapsulation;
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
        for (byte i = 0; i < EEPROM32B_1.length; i++)//either this or the other line
        {
            EEPROM32B_1[i] = 0x00;
        }
//        random.nextBytes(EEPROM32B_1, (short)0, (short)32);
        random.close();
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.keccak.doFinal(EEPROM32B_1, EEPROM32B_2);
        this.keccak.doFinal(this.keyPair.publicKey, EEPROM32B_1);
        Util.arrayCopyNonAtomic(EEPROM32B_2, (short)0, EEPROM64B_1, (short)0, (short)EEPROM32B_2.length);
        Util.arrayCopyNonAtomic(EEPROM32B_1, (short)0, EEPROM64B_1, (short)EEPROM32B_2.length, (short)EEPROM32B_1.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        this.keccak.doFinal(EEPROM64B_1, EEPROM64B_2);
        Util.arrayCopyNonAtomic(EEPROM64B_2, KyberParams.paramsSymBytes, EEPROM32B_1, (short)0, (short)EEPROM32B_1.length);
        this.encrypt(EEPROM32B_2, this.keyPair.publicKey, EEPROM32B_1);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.keccak.doFinal(this.returnArray, EEPROM32B_1);
        Util.arrayCopyNonAtomic(EEPROM64B_2, (short)0, EEPROM64B_1, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(EEPROM32B_1, (short)0, EEPROM64B_1, KyberParams.paramsSymBytes, (short)EEPROM32B_1.length);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        this.keccak.setShakeDigestLength((short)32);
        this.keccak.doFinal(EEPROM64B_1, EEPROM32B_1);
        this.encapsulation = this.returnArray;
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

        Util.arrayCopyNonAtomic(this.keyPair.privateKey, (short)0, indcpaPrivateKey, (short)0, (short)indcpaPrivateKey.length);
        Util.arrayCopyNonAtomic(this.keyPair.privateKey, (short)indcpaPrivateKey.length, keyPair.publicKey, (short)0, (short)keyPair.publicKey.length);
        this.decrypt(this.encapsulation, indcpaPrivateKey, EEPROM32B_2);//begin EEPROM32B_2
        short ski = (short)(privateKeyBytes - (2 * KyberParams.paramsSymBytes));
        Util.arrayCopyNonAtomic(EEPROM32B_2, (short)0, EEPROM64B_2, (short)0, (short)32);//begin EEPROM64B_2
        Util.arrayCopyNonAtomic(this.keyPair.privateKey, ski, EEPROM64B_2, (short)32, KyberParams.paramsSymBytes);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        this.keccak.doFinal(EEPROM64B_2, EEPROM64B_1);//end EEPROM64B_2, begin EEPROM64B_1
        Util.arrayCopyNonAtomic(EEPROM64B_1, KyberParams.paramsSymBytes, EEPROM32B_1, (short)0, (short)32);//begin EEPROM32B_1
        this.encrypt(EEPROM32B_2, keyPair.publicKey, EEPROM32B_1);//end EEPROM32B_1
        byte fail = this.constantTimeCompare(this.encapsulation, this.returnArray);
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.keccak.doFinal(this.encapsulation, EEPROM32B_1);//begin EEPROM32B_1
        short index = (short)(privateKeyBytes - KyberParams.paramsSymBytes);
        for (byte i = 0; i < KyberParams.paramsSymBytes; i++)
        {
            byte privateKeyIndex = (byte)(this.keyPair.privateKey[index] & (byte)0xFF);
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
        //mp = EEPROM384

        this.unpackCiphertext(packedCipherText, this.paramsK);//begin EEPROM384S_X_PARAMS_K_2, begin EEPROM384_2
        this.unpackPrivateKey(privateKey, this.paramsK, EEPROM384S_X_PARAMS_K_1);//begin EEPROM384S_X_PARAMS_K_1
        Poly.getInstance().polyVectorNTT(EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorPointWiseAccMont(EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, this.paramsK, EEPROM384);//end EEPROM384S_X_PARAMS_K_1, begin EEPROM384, end EEPROM384S_X_PARAMS_K_2
        Poly.getInstance().polyInvNTTMont(EEPROM384);
        Poly.getInstance().polySub(EEPROM384_2, EEPROM384);//end EEPROM384
        Poly.getInstance().polyReduce(EEPROM384_2);
        Poly.getInstance().polyToMsg(EEPROM384_2, msg);//end EEPROM384_2
    }

    //phase 2 smart card ok, opt ok
    public void encrypt(byte[] m, byte[] publicKey, byte[] coins)
    {
        //cannot use EEPROM64B_1
        //cannot use EEPROM64B_2
        //cannot use EEPROM384
        //cannot use EEPROM384S_X_PARAMS_K_1

        //m = EEPROM32B_2
        //coins = EEPROM32B_1
        //EEPROM384S_X_PARAMS_K_2 = sp
        //EEPROM384S_X_PARAMS_K_3 = ep
        //EEPROM384S_X_PARAMS_K_4 = bp
        //EEPROM384_2 = epp
        //at = EEPROM384S_X_PARAMS_K_X_PARAMS_K
        //k = EEPROM256S_1

        Poly.getInstance().polyFromData(m, EEPROM256S_1);
        this.unpackPublicKey(publicKey, paramsK);
        this.generateMatrix(this.seed, true, EEPROM384S_X_PARAMS_K_X_PARAMS_K);
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
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384S_X_PARAMS_K_X_PARAMS_K, (short)(i*paramsK*384), this.EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*paramsK));
            Poly.getInstance().polyVectorPointWiseAccMont(this.EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, paramsK, EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384, (short)0,EEPROM384S_X_PARAMS_K_4,(short)(i*384),(short)384);
        }
        Poly.getInstance().polyVectorPointWiseAccMont(this.publicKeyPolyvec, EEPROM384S_X_PARAMS_K_2, paramsK, EEPROM384);
        Poly.getInstance().polyVectorInvNTTMont(EEPROM384S_X_PARAMS_K_4, paramsK);
        Poly.getInstance().polyInvNTTMont(EEPROM384);
        Poly.getInstance().polyVectorAdd(EEPROM384S_X_PARAMS_K_4, EEPROM384S_X_PARAMS_K_3, paramsK);
        Poly.getInstance().polyAdd(EEPROM384, EEPROM384_2);
        Poly.getInstance().polyAdd(EEPROM384, EEPROM256S_1);
        Poly.getInstance().polyVectorReduce(EEPROM384S_X_PARAMS_K_4, paramsK);
        Poly.getInstance().polyReduce(EEPROM384);
        this.packCiphertext(EEPROM384S_X_PARAMS_K_4, EEPROM384, paramsK);
    }

    //phase 1 smart card ok, opt ok
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
                Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384, (short)0, result, (short)(((i*this.paramsK)+j)*384), (short)384);
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
//        random.nextBytes(this.EEPROM32B_2, (short)0, (short)32);
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
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//        random.nextBytes(this.EEPROM32B_1, (short)0, (short)32);
        random.close();
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

    //phase 3, smart card ok, opt ok
    public void unpackCiphertext(byte[] c, byte paramsK)
    {
        //bp = EEPROM384S_X_PARAMS_K_2
        Util.arrayCopyNonAtomic(c, (short)0, bCompress, (short)0, (short)bCompress.length);
        Util.arrayCopyNonAtomic(c, (short)bCompress.length, vc, (short)0, (short)vc.length);
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
        //partlyPublicKey = EEPROM768B_1

        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM768B_1, (short)0, KyberParams.paramsPolyvecBytesK512);
                Poly.getInstance().polyVectorFromBytes(EEPROM768B_1, paramsK, this.publicKeyPolyvec);
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