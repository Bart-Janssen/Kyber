package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.JCSystem;
import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Models.KyberParams;
import java.util.Arrays;

public final class Poly
{
    private static Poly instance;

    public static Poly getInstance()
    {
        if (instance == null) instance = new Poly();
        return instance;
    }

    private static short[] multiplied;
    private static short[] jc;

    private Poly()
    {
        multiplied = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        jc = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
    }

    protected static void print(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : data)
        {
            sb.append(String.format("%02X ", b));
        }
        System.out.print(sb);
        System.out.println();
    }

    public void arrayCopyNonAtomic(short[] src, short srcIndex, short[] dst, short dstIndex, short length)
    {
        for (short i = 0; i < length; i++)
        {
            dst[(short)(dstIndex+i)] = src[(short)(srcIndex+i)];
        }
    }

    public final static short[] nttZetas = new short[]{
            2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
            2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
            732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
            1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
            107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
            430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
            1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
            418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
            1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
            478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
    };

    public final static short[] nttZetasInv = new short[]{
            1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
            1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
            1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
            1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
            3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
            1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
            1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
            2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
            829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
            3127, 3042, 1907, 1836, 1517, 359, 758, 1441
    };
    protected short[] poly = new short[KyberParams.paramsPolyBytes];
    protected short[][] polyvec;

    public byte[] compressPoly(short[] polyA, byte paramsK) {
        byte[] t = new byte[8];
        polyA = this.polyConditionalSubQ(polyA);
        int rr = 0;
        byte[] r;
        switch (paramsK) {
            //Only kyber 512 for now
            case 2:
            case 3: default:
                r = new byte[KyberParams.paramsPolyCompressedBytesK768];
                for (int i = 0; i < KyberParams.paramsN / 8; i++) {
                    for (int j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 15);
                    }
                    r[rr + 0] = (byte) (t[0] | (t[1] << 4));
                    r[rr + 1] = (byte) (t[2] | (t[3] << 4));
                    r[rr + 2] = (byte) (t[4] | (t[5] << 4));
                    r[rr + 3] = (byte) (t[6] | (t[7] << 4));
                    rr = rr + 4;
                }
                break;
//            default:
//                r = new byte[KyberParams.paramsPolyCompressedBytesK1024];
//                for (int i = 0; i < KyberParams.paramsN / 8; i++) {
//                    for (int j = 0; j < 8; j++) {
//                        t[j] = (byte) (((((polyA[8 * i + j]) << 5) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 31);
//                    }
//                    r[rr + 0] = (byte) ((t[0] >> 0) | (t[1] << 5));
//                    r[rr + 1] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
//                    r[rr + 2] = (byte) ((t[3] >> 1) | (t[4] << 4));
//                    r[rr + 3] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
//                    r[rr + 4] = (byte) ((t[6] >> 2) | (t[7] << 3));
//                    rr = rr + 5;
//                }
        }

        return r;
    }

    public short[] decompressPoly(byte[] a, byte paramsK) {
        short[] r = new short[KyberParams.paramsPolyBytes];
        int aa = 0;
        switch (paramsK) {
            //Only kyber 512 for now
            case 2:
            case 3: default:
                for (int i = 0; i < KyberParams.paramsN / 2; i++) {
                    r[2 * i + 0] = (short) (((((int) (a[aa] & 0xFF) & 15) * KyberParams.paramsQ) + 8) >> 4);
                    r[2 * i + 1] = (short) (((((int) (a[aa] & 0xFF) >> 4) * KyberParams.paramsQ) + 8) >> 4);
                    aa = aa + 1;
                }
                break;
//            default:
//                long[] t = new long[8];
//                for (int i = 0; i < KyberParams.paramsN / 8; i++) {
//                    t[0] = (long) ((int) (a[aa + 0] & 0xFF) >> 0) & 0xFF;
//                    t[1] = (long) ((byte) (((int) (a[aa + 0] & 0xFF) >> 5)) | (byte) ((int) (a[aa + 1] & 0xFF) << 3)) & 0xFF;
//                    t[2] = (long) ((int) (a[aa + 1] & 0xFF) >> 2) & 0xFF;
//                    t[3] = (long) ((byte) (((int) (a[aa + 1] & 0xFF) >> 7)) | (byte) ((int) (a[aa + 2] & 0xFF) << 1)) & 0xFF;
//                    t[4] = (long) ((byte) (((int) (a[aa + 2] & 0xFF) >> 4)) | (byte) ((int) (a[aa + 3] & 0xFF) << 4)) & 0xFF;
//                    t[5] = (long) ((int) (a[aa + 3] & 0xFF) >> 1) & 0xFF;
//                    t[6] = (long) ((byte) (((int) (a[aa + 3] & 0xFF) >> 6)) | (byte) ((int) (a[aa + 4] & 0xFF) << 2)) & 0xFF;
//                    t[7] = ((long) ((int) (a[aa + 4] & 0xFF) >> 3)) & 0xFF;
//                    aa = aa + 5;
//                    for (int j = 0; j < 8; j++) {
//                        r[8 * i + j] = (short) ((((long) (t[j] & 31) * (KyberParams.paramsQ)) + 16) >> 5);
//                    }
//                }
        }
        return r;
    }

    //Smart card ok, need optimization
    public byte[] polyToBytes(short[] a)
    {
        short t0, t1;
        byte[] r = new byte[KyberParams.paramsPolyBytes];
        a = this.polyConditionalSubQ(a);
        for (short i = 0; i < (short)(KyberParams.paramsN / (byte)2); i++)
        {
            t0 = ((short)(a[(short)((byte)2 * i)] & (short)0xFFFF));
            t1 = (short)((a[(short)((byte)2 * i + (byte)1)]) & (short)0xFFFF);
            r[(short)((byte)3 * i + (byte)0)] = (byte) (t0 >>  (byte)0);
            r[(short)((byte)3 * i + (byte)1)] = (byte) ((t0 >> (byte)8) | (t1 << (byte)4));
            r[(short)((byte)3 * i + (byte)2)] = (byte) (t1 >>  (byte)4);
        }
        return r;
    }

    public byte[] polyToBytessc(short[] a) {
        int t0, t1;
        byte[] r = new byte[KyberParams.paramsPolyBytes];
        a = this.polyConditionalSubQ(a);
        for (int i = 0; i < KyberParams.paramsN / 2; i++) {
            t0 = ((int) (a[2 * i] & 0xFFFF));
            t1 = ((int) (a[2 * i + 1]) & 0xFFFF);
            r[3 * i + 0] = (byte) (t0 >> 0);
            r[3 * i + 1] = (byte) ((int) (t0 >> 8) | (int) (t1 << 4));
            r[3 * i + 2] = (byte) (t1 >> 4);
        }
        return r;
    }

    public short[] polyFromBytes(byte[] a) {
        short[] r = new short[KyberParams.paramsPolyBytes];
        for (int i = 0; i < KyberParams.paramsN / 2; i++) {
            r[2 * i] = (short) ((((a[3 * i + 0] & 0xFF) >> 0) | ((a[3 * i + 1] & 0xFF) << 8)) & 0xFFF);
            r[2 * i + 1] = (short) ((((a[3 * i + 1] & 0xFF) >> 4) | ((a[3 * i + 2] & 0xFF) << 4)) & 0xFFF);
        }
        return r;
    }

    public short[] polyFromData(byte[] msg) {
        short[] r = new short[KyberParams.paramsN];
        short mask;
        for (int i = 0; i < KyberParams.paramsN / 8; i++) {
            for (int j = 0; j < 8; j++) {
                mask = (short) (-1 * (short) (((msg[i] & 0xFF) >> j) & 1));
                r[8 * i + j] = (short) (mask & (short) ((KyberParams.paramsQ + 1) / 2));
            }
        }
        return r;
    }

    public byte[] polyToMsg(short[] a) {
        byte[] msg = new byte[KyberParams.paramsSymBytes];
        int t;
        a = this.polyConditionalSubQ(a);
        for (int i = 0; i < KyberParams.paramsN / 8; i++) {
            msg[i] = 0;
            for (int j = 0; j < 8; j++) {
                t = (int) ((((((int) (a[8 * i + j])) << 1) + (KyberParams.paramsQ / 2)) / KyberParams.paramsQ) & 1);
                msg[i] = (byte) (msg[i] | (t << j));
            }
        }
        return msg;
    }

    //Smart card ok, needs optimization
    public short[] getNoisePoly(byte[] seed, byte nonce, byte paramsK)
    {
        short l;
        byte[] p;
        switch (paramsK)
        {
            //this part is already supported for all three kyber
            case 2:
                l = KyberParams.paramsETAK512 * KyberParams.paramsN / 4;
                break;
            default:
                l = KyberParams.paramsETAK768K1024 * KyberParams.paramsN / 4;
        }
        p = this.generatePRFByteArray(l, seed, nonce);
        return this.generateCBDPoly(p, paramsK);
    }

    public long convertByteTo24BitUnsignedInt(byte[] x)
    {
        long r = (long) (x[0] & 0xFF);
        r = r | (long) ((long) (x[1] & 0xFF) << 8);
        r = r | (long) ((long) (x[2] & 0xFF) << 16);
        return r;
    }

    public long convertByteTo32BitUnsignedInt(byte[] x) {
        long r = (long) (x[0] & 0xFF);
        r = r | (long) ((long) (x[1] & 0xFF) << 8);
        r = r | (long) ((long) (x[2] & 0xFF) << 16);
        r = r | (long) ((long) (x[3] & 0xFF) << 24);
        return r;
    }

    //smart card ok, need optimization
    public short[] generateCBDPoly(byte[] buf, byte paramsK)
    {
        byte[] d = new byte[3];
        byte[] t = new byte[3];
        byte[] tempT = new byte[3];

        short a, b;
        short[] r = new short[KyberParams.paramsPolyBytes];
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
                for (byte i = 0; i < KyberParams.paramsN / 4; i++)
                {
                    //t = Poly.convertByteTo24BitUnsignedInt(Arrays.copyOfRange(buf, (3 * i), buf.length));
                    t[0] = buf[(short)(3*i+2)];
                    t[1] = buf[(short)(3*i+1)];
                    t[2] = buf[(short)(3*i+0)];

                    //t & 0x00249249
                    d[0] = (byte)(t[0] & 0x24);
                    d[1] = (byte)(t[1] & 0x92);
                    d[2] = (byte)(t[2] & 0x49);

                    //t >> 1
                    t[2] = (byte)(((t[2]&0xFF)>>1) | ((t[1]&0xFF)<<7));
                    t[1] = (byte)(((t[1]&0xFF)>>1) | ((t[0]&0xFF)<<7));
                    t[0] = (byte)(((t[0]&0xFF)>>1));

                    //(t >> 1) & 0x00249249
                    tempT[0] = (byte)(t[0] & 0x24);
                    tempT[1] = (byte)(t[1] & 0x92);
                    tempT[2] = (byte)(t[2] & 0x49);

                    //d = d + (t >> 1) & 0x00249249
                    Arithmetic.sumByteArrays(d,tempT);

                    //t >> 1
                    t[2] = (byte)(((t[2]&0xFF)>>1) | ((t[1]&0xFF)<<7));
                    t[1] = (byte)(((t[1]&0xFF)>>1) | ((t[0]&0xFF)<<7));
                    t[0] = (byte)(((t[0]&0xFF)>>1));

                    //(t >> 1) & 0x00249249
                    tempT[0] = (byte)(t[0] & 0x24);
                    tempT[1] = (byte)(t[1] & 0x92);
                    tempT[2] = (byte)(t[2] & 0x49);

                    //d = d + (t >> 1) & 0x00249249
                    Arithmetic.sumByteArrays(d,tempT);

                    //for (int j = 0; j < 4; j++) //replaced loop with static 4 assignments
                    //See generateCBDPoly.txt
                    a = (short)(((d[2]&0xFF)>>0) & 0x7);                          //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((d[1]&0xFF)<<5) | ((d[2]&0xFF)>>3)) & 0x7);//3  //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    r[(short)(4 * i + 0)] = (short)(a - b);                                //r[4 * i + j] = (short)(a - b);

                    a = (short)((((d[1]&0xFF)<<2) | ((d[2]&0xFF)>>6)) & 0x7);//6  //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((d[0]&0xFF)<<7) | ((d[1]&0xFF)>>1)) & 0x7);//9  //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    r[(short)(4 * i + 1)] = (short)(a - b);                                //r[4 * i + j] = (short)(a - b);

                    a = (short)((((d[0]&0xFF)<<4) | ((d[1]&0xFF)>>4)) & 0x7);//12 //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((d[0]&0xFF)<<1) | ((d[1]&0xFF)>>7)) & 0x7);//15 //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    r[(short)(4 * i + 2)] = (short)(a - b);                                //r[4 * i + j] = (short)(a - b);

                    a = (short)(((d[0]&0xFF)>>2) & 0x7);//18                      //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)(((d[0]&0xFF)>>5) & 0x7);//21                      //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    r[(short)(4 * i + 3)] = (short)(a - b);                         //r[4 * i + j] = (short)(a - b);
                }
                break;
//            default:
//                for (int i = 0; i < KyberParams.paramsN / 8; i++) {
//                    t = Poly.convertByteTo32BitUnsignedInt(Arrays.copyOfRange(buf, (4 * i), buf.length));
//                    d = t & 0x55555555;
//                    d = d + ((t >> 1) & 0x55555555);
//                    for (int j = 0; j < 8; j++) {
//                        a = (short) ((d >> (4 * j + 0)) & 0x3);
//                        b = (short) ((d >> (4 * j + KyberParams.paramsETAK768K1024)) & 0x3);
//                        r[8 * i + j] = (short) (a - b);
//                    }
//                }
        }
        return r;
    }

    //smart card ok, need optimization
    public byte[] generatePRFByteArray(short l, byte[] key, byte nonce)
    {
        byte[] hash = new byte[l];
        byte[] newKey = new byte[(byte)(key.length + 1)];
        Util.arrayCopyNonAtomic(key, (short)0, newKey, (short)0, (short)key.length);
        newKey[key.length] = nonce;
        Keccak keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength(l);
        keccak.doFinal(newKey, hash);
        return hash;
    }

    // smart card ok
    public short[] polyNTT(short[] r)
    {
        short j = 0;
        short k = 1;
        for (short l = (short)128; l >= 2; l >>= 1)
        {
            for (short start = 0; start < (short)256; start = (short)(j + l))
            {
                short zeta = nttZetas[k];
                k = (short)(k + (short)1);
                for (j = start; j < (short)(start + l); j++)
                {
                    short t = this.modQMulMont(zeta, r[(short)(j + l)]);
                    r[(short)(j + l)] = (short)(r[j] - t);
                    r[j] = (short)(r[j] + t);
                }
            }
        }
        return r;
    }

    //smart card ok
    public short modQMulMont(short a, short b)
    {
        //(long) ((long) a * (long) b)
        Arithmetic.multiplyShorts(a,b, jc);
        return montgomeryReduce(jc);
    }

    //smart card ok, optimize jc away
    public short montgomeryReduce(short[] jc)
    {
        //short u = (short) (a * KyberParams.paramsQinv);
        short u = (short) ((jc[1] * KyberParams.paramsQinv) & (short)0xFFFF);

        //int t = (int) (u * KyberParams.paramsQ);
        Arithmetic.multiplyShorts(KyberParams.paramsQ,u, multiplied);

        //t = (int) (a - t);
        Arithmetic.subtract(jc,multiplied);

        // t >>= 16;
        return jc[0];
    }

    public short[] polyInvNTTMont(short[] r) {
        return this.invNTT(r);
    }

    public short[] invNTT(short[] r) {
        int j = 0;
        int k = 0;
        for (int l = 2; l <= 128; l <<= 1) {
            for (int start = 0; start < 256; start = j + l) {
                short zeta = Poly.nttZetasInv[k];
                k = k + 1;
                for (j = start; j < start + l; j++) {
                    short t = r[j];
                    r[j] = this.barrettReduce((short) (t + r[j + l]));
                    r[j + l] = (short) (t - r[j + l]);
                    r[j + l] = this.modQMulMont(zeta, r[j + l]);
                }
            }
        }
        for (j = 0; j < 256; j++) {
            r[j] = this.modQMulMont(r[j], nttZetasInv[127]);
        }
        return r;
    }

    //Optimize return as void since it returns input anyway
    public short[] polyBaseMulMont(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.paramsN / 4; i++) {
            short[] rx = this.baseMultiplier(
                    polyA[4 * i + 0], polyA[4 * i + 1],
                    polyB[4 * i + 0], polyB[4 * i + 1],
                    (short) Poly.nttZetas[64 + i]
            );
            short[] ry = this.baseMultiplier(
                    polyA[4 * i + 2], polyA[4 * i + 3],
                    polyB[4 * i + 2], polyB[4 * i + 3],
                    (short) (-1 * Poly.nttZetas[64 + i])
            );
            polyA[4 * i + 0] = rx[0];
            polyA[4 * i + 1] = rx[1];
            polyA[4 * i + 2] = ry[0];
            polyA[4 * i + 3] = ry[1];
        }
        return polyA;
    }

    public short[] baseMultiplier(short a0, short a1, short b0, short b1, short zeta) {
        short[] r = new short[2];
        r[0] = this.modQMulMont(a1, b1);
        r[0] = this.modQMulMont(r[0], zeta);
        r[0] = (short) (r[0] + this.modQMulMont(a0, b0));
        r[1] = this.modQMulMont(a0, b1);
        r[1] = (short) (r[1] + this.modQMulMont(a1, b0));
        return r;
    }

    public short[] polyToMont(short[] polyR) {
        for (int i = 0; i < KyberParams.paramsN; i++) {
            polyR[i] = this.montgomeryReduce((int) (polyR[i] * 1353));
        }
        return polyR;
    }

    public short montgomeryReduce(int a) {
        short u = (short) (a * KyberParams.paramsQinv);
        int t = (int) (u * KyberParams.paramsQ);
        t = (int) (a - t);
        t >>= 16;
        return (short) t;
    }

    //smart card ok
    public short[] polyReduce(short[] r)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            r[i] = this.barrettReduce(r[i]);
        }
        return r;
    }

    //smart card ok
    public short barrettReduce(short a)
    {
        //long shift = (((long) 1) << 26);
        //short v = (short) ((shift + (KyberParams.paramsQ / 2)) / KyberParams.paramsQ);
        short v = (short)20159; //All static values, no calculation needed

        //short t = (short) ((v * a) >> 26);
        Arithmetic.multiplyShorts(v,a,multiplied);
        short t = (short)(multiplied[0]>>10);// >> (26-16) = 10

        t = (short)(t * KyberParams.paramsQ);
        return (short)(a - t);
    }

    public short[] polyConditionalSubQ(short[] r) {
        for (int i = 0; i < KyberParams.paramsN; i++) {
            r[i] = this.conditionalSubQ(r[i]);
        }
        return r;
    }

    public short conditionalSubQ(short a) {
        a = (short) (a - KyberParams.paramsQ);
        a = (short) (a + ((int) ((int) a >> 15) & KyberParams.paramsQ));
        return a;
    }

    public short[] polyAdd(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.paramsN; i++) {
            polyA[i] = (short) (polyA[i] + polyB[i]);
        }
        return polyA;
    }

    public short[] polySub(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.paramsN; i++) {
            polyA[i] = (short) (polyA[i] - polyB[i]);
        }
        return polyA;
    }

    //smart card ok (might not want to do this at all)
    public short[] generateNewPolyVector(byte paramsK)
    {
        return new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
    }

    public byte[] compressPolyVector(short[][] a, byte paramsK) {
        this.polyVectorCSubQ(a, paramsK);
        int rr = 0;
        byte[] r;
        long[] t;
        switch (paramsK) {
            //Only kyber 512 for now
            case 2: default:
                r = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
//            case 3:
//                r = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
//                break;
//            default:
//                r = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        }

        switch (paramsK) {
            //Only kyber 512 for now
            case 2:
            case 3: default:
                t = new long[4];
                for (byte i = 0; i < paramsK; i++) {
                    for (int j = 0; j < KyberParams.paramsN / 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            t[k] = ((long) (((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x3ff);
                        }
                        r[rr + 0] = (byte) (t[0] >> 0);
                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 2));
                        r[rr + 2] = (byte) ((t[1] >> 6) | (t[2] << 4));
                        r[rr + 3] = (byte) ((t[2] >> 4) | (t[3] << 6));
                        r[rr + 4] = (byte) ((t[3] >> 2));
                        rr = rr + 5;
                    }
                }
                break;
//            default:
//                t = new long[8];
//                for (byte i = 0; i < paramsK; i++) {
//                    for (int j = 0; j < KyberParams.paramsN / 8; j++) {
//                        for (int k = 0; k < 8; k++) {
//                            t[k] = ((long) (((long) ((long) (a[i][8 * j + k]) << 11) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x7ff);
//                        }
//                        r[rr + 0] = (byte) ((t[0] >> 0));
//                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 3));
//                        r[rr + 2] = (byte) ((t[1] >> 5) | (t[2] << 6));
//                        r[rr + 3] = (byte) ((t[2] >> 2));
//                        r[rr + 4] = (byte) ((t[2] >> 10) | (t[3] << 1));
//                        r[rr + 5] = (byte) ((t[3] >> 7) | (t[4] << 4));
//                        r[rr + 6] = (byte) ((t[4] >> 4) | (t[5] << 7));
//                        r[rr + 7] = (byte) ((t[5] >> 1));
//                        r[rr + 8] = (byte) ((t[5] >> 9) | (t[6] << 2));
//                        r[rr + 9] = (byte) ((t[6] >> 6) | (t[7] << 5));
//                        r[rr + 10] = (byte) ((t[7] >> 3));
//                        rr = rr + 11;
//                    }
//                }
        }
        return r;
    }

    public short[][] decompressPolyVector(byte[] a, byte paramsK) {
        short[][] r = new short[paramsK][KyberParams.paramsPolyBytes];
        int aa = 0;
        int[] t;
        switch (paramsK) {
            //Only kyber 512 for now
            case 2:
            case 3: default:
                t = new int[4]; // has to be unsigned..
                for (byte i = 0; i < paramsK; i++) {
                    for (int j = 0; j < (KyberParams.paramsN / 4); j++) {
                        t[0] = ((a[aa + 0] & 0xFF) >> 0) | ((a[aa + 1] & 0xFF) << 8);
                        t[1] = ((a[aa + 1] & 0xFF) >> 2) | ((a[aa + 2] & 0xFF) << 6);
                        t[2] = ((a[aa + 2] & 0xFF) >> 4) | ((a[aa + 3] & 0xFF) << 4);
                        t[3] = ((a[aa + 3] & 0xFF) >> 6) | ((a[aa + 4] & 0xFF) << 2);
                        aa = aa + 5;
                        for (int k = 0; k < 4; k++) {
                            r[i][4 * j + k] = (short) (((long) (t[k] & 0x3FF) * (long) (KyberParams.paramsQ) + 512) >> 10);
                        }
                    }
                }
                break;
//            default:
//                t = new int[8]; // has to be unsigned..
//                for (byte i = 0; i < paramsK; i++) {
//                    for (int j = 0; j < (KyberParams.paramsN / 8); j++) {
//                        t[0] = (((a[aa + 0] & 0xff) >> 0) | ((a[aa + 1] & 0xff) << 8));
//                        t[1] = (((a[aa + 1] & 0xff) >> 3) | ((a[aa + 2] & 0xff) << 5));
//                        t[2] = (((a[aa + 2] & 0xff) >> 6) | ((a[aa + 3] & 0xff) << 2) | ((a[aa + 4] & 0xff) << 10));
//                        t[3] = (((a[aa + 4] & 0xff) >> 1) | ((a[aa + 5] & 0xff) << 7));
//                        t[4] = (((a[aa + 5] & 0xff) >> 4) | ((a[aa + 6] & 0xff) << 4));
//                        t[5] = (((a[aa + 6] & 0xff) >> 7) | ((a[aa + 7] & 0xff) << 1) | ((a[aa + 8] & 0xff) << 9));
//                        t[6] = (((a[aa + 8] & 0xff) >> 2) | ((a[aa + 9] & 0xff) << 6));
//                        t[7] = (((a[aa + 9] & 0xff) >> 5) | ((a[aa + 10] & 0xff) << 3));
//                        aa = aa + 11;
//                        for (int k = 0; k < 8; k++) {
//                            r[i][8 * j + k] = (short) (((long) (t[k] & 0x7FF) * (long) (KyberParams.paramsQ) + 1024) >> 11);
//                        }
//                    }
//                }
        }
        return r;
    }

    //Smart card ok, need optimize, r as parameter
    public byte[] polyVectorToBytes(short[] polyA, byte paramsK)
    {
        byte[] r = new byte[(short)(paramsK * KyberParams.paramsPolyBytes)];
        short[] row = new short[KyberParams.paramsPolyBytes];
        for (byte i = 0; i < paramsK; i++)
        {
            this.arrayCopyNonAtomic(polyA, (short)(i * KyberParams.paramsPolyBytes), row, (short)0, KyberParams.paramsPolyBytes);
            byte[] byteA = polyToBytes(row);
            Util.arrayCopyNonAtomic(byteA, (short)0, r, (short)(i * KyberParams.paramsPolyBytes), (short)byteA.length);
        }
        return r;
    }

    public short[][] polyVectorFromBytes(byte[] polyA, byte paramsK) {
        short[][] r = new short[paramsK][KyberParams.paramsPolyBytes];
        for (byte i = 0; i < paramsK; i++) {
            int start = (i * KyberParams.paramsPolyBytes);
            int end = (i + 1) * KyberParams.paramsPolyBytes;
            r[i] = this.polyFromBytes(Arrays.copyOfRange(polyA, start, end));
        }
        return r;
    }

    //smart card ok, need opt
    //k = 2, r = 384 || 384
    public short[] polyVectorNTT(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            short[] row = new short[(short)384];
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), row, (short)0, (short)384);
            row = polyNTT(row);
            this.arrayCopyNonAtomic(row, (short)0, r, (short)(i * (short)384), (short)384);
        }
        return r;
    }

    public short[][] polyVectorInvNTTMont(short[][] r, byte paramsK) {
        for (byte i = 0; i < paramsK; i++) {
            r[i] = this.polyInvNTTMont(r[i]);
        }
        return r;
    }

    public short[] polyVectorPointWiseAccMont(short[] polyA, short[] polyB, byte paramsK)
    {
        short rowSize = 384;
        short[] Brow = new short[rowSize];
        this.arrayCopyNonAtomic(polyB, (short)0, Brow, (short)0, rowSize);
        short[] polyArow = new short[rowSize];
        this.arrayCopyNonAtomic(polyA, (short)0, polyArow, (short)0, rowSize);
        //variable r can be removed since polyBaseMulMont returns polyArow
        short[] r = this.polyBaseMulMont(polyArow, Brow);
        for (byte i = 1; i < paramsK; i++)
        {
            short[] Arow = new short[rowSize];
            this.arrayCopyNonAtomic(polyA, (short)(i*rowSize), Arow, (short)0, rowSize);
            this.arrayCopyNonAtomic(polyB, (short)(i*rowSize), Brow, (short)0, rowSize);
            short[] t = this.polyBaseMulMont(Arow, Brow);
            r = this.polyAdd(r, t);
        }
        return polyReduce(r);
    }

    ////smart card ok, need opt
    // k = 2, r = 384 || 384
    public short[] polyVectorReduce(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            short[] row = new short[(short)384];
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), row, (short)0, (short)384);
            row = polyReduce(row);
            this.arrayCopyNonAtomic(row, (short)0, r, (short)(i * (short)384), (short)384);
        }
        return r;
    }

    public short[][] polyVectorCSubQ(short[][] r, byte paramsK) {
        for (byte i = 0; i < paramsK; i++) {
            r[i] = this.polyConditionalSubQ(r[i]);
        }
        return r;
    }

    public short[] polyVectorAdd(short[] polyA, short[] polyB, byte paramsK)
    {
        short rowSize = 384;
        for (byte i = 0; i < paramsK; i++)
        {
            for (short j = 0; j < rowSize; j++)
            {
                polyA[(i * rowSize) + j] += polyB[(i * rowSize) + j];
            }
        }
        return polyA;
    }
}