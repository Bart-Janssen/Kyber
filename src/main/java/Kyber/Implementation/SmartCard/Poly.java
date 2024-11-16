package Kyber.Implementation.SmartCard;

import Kyber.Implementation.SmartCard.dummy.JCSystem;
import Kyber.Implementation.SmartCard.dummy.Util;
import Kyber.Models.KyberParams;

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
    private static short[] result;
    private static short[] RAM32S_1;
    private static short[] RAM384S_1;
    private static short[] RAM384S_2;
    private static byte[] RAM384B_1;
    private static byte[] RAM33B_1;
    private static byte[] RAM4B_1;
    private static byte[] RAM4B_2;
    private static byte[] RAM4B_3;
    private static short[] RAM2S_1;
    private static short[] RAM2S_2;

    private Poly()
    {
        multiplied = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        jc = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        result = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        RAM384S_1 = JCSystem.makeTransientShortArray((short)384, JCSystem.CLEAR_ON_DESELECT);
        RAM384S_2 = JCSystem.makeTransientShortArray((short)384, JCSystem.CLEAR_ON_DESELECT);
        RAM384B_1 = JCSystem.makeTransientByteArray((short)384, JCSystem.CLEAR_ON_DESELECT);
        RAM33B_1 = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_DESELECT);
        RAM32S_1 = JCSystem.makeTransientShortArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        RAM4B_1 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        RAM4B_2 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        RAM4B_3 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        RAM2S_1 = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        RAM2S_2 = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
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

    public final static short[] nttZetasInv = new short[]
    {
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

    //smart card ok, opt ok
    public void compressPoly(short[] polyA, byte paramsK, byte[] r)
    {
        this.polyConditionalSubQ(polyA);
        short rr = 0;
        switch (paramsK)
        {
            case 2:
            case 3:
                for (byte i = 0; i < KyberParams.paramsN / 8; i++)
                {
                    for (byte j = 0; j < 8; j++)
                    {
                        //t[j] = (byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 15);

                        //((polyA[8 * i + j]) << 4)
                        short shHigh = (short)(polyA[(short)(8 * i + j)] >> 12);
                        short shLow = (short)(polyA[(short)(8 * i + j)] << 4);

                        //(((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2))
                        Arithmetic.add(shHigh, shLow, (short)0, (short)(KyberParams.paramsQ / 2), result);

                        //((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ))
                        Arithmetic.divide(result[0], result[1], (short)0, KyberParams.paramsQ, result);

                        //(byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 15)
                        //RAM384B_1 = t = new byte[8];
                        RAM384B_1[j] = (byte)(result[1] & 15);
                    }
                    r[(short)(rr + 0)] = (byte)(RAM384B_1[0] | (RAM384B_1[1] << 4));
                    r[(short)(rr + 1)] = (byte)(RAM384B_1[2] | (RAM384B_1[3] << 4));
                    r[(short)(rr + 2)] = (byte)(RAM384B_1[4] | (RAM384B_1[5] << 4));
                    r[(short)(rr + 3)] = (byte)(RAM384B_1[6] | (RAM384B_1[7] << 4));
                    rr+=4;
                }
                break;
            default:
                byte[] t = new byte[8];
                for (byte i = 0; i < KyberParams.paramsN / 8; i++)
                {
                    for (byte j = 0; j < 8; j++)
                    {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 5) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 31);
                    }
                    r[rr + 0] = (byte) ((t[0] >> 0) | (t[1] << 5));
                    r[rr + 1] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                    r[rr + 2] = (byte) ((t[3] >> 1) | (t[4] << 4));
                    r[rr + 3] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                    r[rr + 4] = (byte) ((t[6] >> 2) | (t[7] << 3));
                    rr+=5;
                }
        }
    }

    //Smart card ok, opt ok
    public void decompressPoly(byte[] a, byte paramsK, short[] r)
    {
        short aa = 0;
        switch (paramsK)
        {
            case 2:
            case 3:
                for (short i = 0; i < KyberParams.paramsN / 2; i++)
                {
                    //(((int) (a[aa] & 0xFF) & 15) * KyberParams.paramsQ)
                    Arithmetic.multiplyShorts((short)((a[aa] & (short)0xFF) & 15), KyberParams.paramsQ, multiplied);
                    //((((int) (a[aa] & 0xFF) & 15) * KyberParams.paramsQ) + 8)
                    Arithmetic.add(multiplied[0], multiplied[1], (short)0, (short)8, multiplied);
                    //r[(short)(2 * i + 0)] = (short) (((((int) (a[aa] & 0xFF) & 15) * KyberParams.paramsQ) + 8) >> 4);
                    r[(short)(2 * i + 0)] = (short)(((multiplied[1]>>4)&(short)0xFFF));

                    //(((int) (a[aa] & 0xFF) >> 4) * KyberParams.paramsQ)
                    Arithmetic.multiplyShorts((short)((a[aa] & 0xFF) >> 4), KyberParams.paramsQ, multiplied);
                    //((((int) (a[aa] & 0xFF) >> 4) * KyberParams.paramsQ) + 8)
                    Arithmetic.add(multiplied[0], multiplied[1], (short)0, (short)8, multiplied);
                    //r[(short)(2 * i + 1)] = (short) (((((int) (a[aa] & 0xFF) >> 4) * KyberParams.paramsQ) + 8) >> 4);
                    r[(short)(2 * i + 1)] = (short)(((multiplied[1]>>4)&(short)0xFFF));
                    aa+=1;
                }
                break;
            default:
                short[] t = new short[8];
                for (byte i = 0; i < KyberParams.paramsN / 8; i++)
                {
                    t[0] = (short)(((int) (a[aa + 0] & 0xFF) >> 0) & 0xFF);
                    t[1] = (short)(((byte) (((int) (a[aa + 0] & 0xFF) >> 5)) | (byte) ((int) (a[aa + 1] & 0xFF) << 3)) & 0xFF);
                    t[2] = (short)(((int) (a[aa + 1] & 0xFF) >> 2) & 0xFF);
                    t[3] = (short)(((byte) (((int) (a[aa + 1] & 0xFF) >> 7)) | (byte) ((int) (a[aa + 2] & 0xFF) << 1)) & 0xFF);
                    t[4] = (short)(((byte) (((int) (a[aa + 2] & 0xFF) >> 4)) | (byte) ((int) (a[aa + 3] & 0xFF) << 4)) & 0xFF);
                    t[5] = (short)(((int) (a[aa + 3] & 0xFF) >> 1) & 0xFF);
                    t[6] = (short)(((byte) (((int) (a[aa + 3] & 0xFF) >> 6)) | (byte) ((int) (a[aa + 4] & 0xFF) << 2)) & 0xFF);
                    t[7] = (short)(((int) (a[aa + 4] & 0xFF) >> 3) & 0xFF);
                    aa+=5;
                    for (byte j = 0; j < 8; j++)
                    {
                        r[8 * i + j] = (short) ((((long) (t[j] & 31) * (KyberParams.paramsQ)) + 16) >> 5);
                    }
                }
        }
    }

    //Smart card ok, opt ok
    public void polyToBytes(short[] a, byte[] r)
    {
        //a = RAM348
        short t0, t1;
        this.polyConditionalSubQ(a);
        for (short i = 0; i < (short)(KyberParams.paramsN / (byte)2); i++)
        {
            t0 = ((short)(a[(short)((byte)2 * i)] & (short)0xFFFF));
            t1 = (short)((a[(short)((byte)2 * i + (byte)1)]) & (short)0xFFFF);
            r[(short)((byte)3 * i + (byte)0)] = (byte) (t0 >>  (byte)0);
            r[(short)((byte)3 * i + (byte)1)] = (byte) ((t0 >> (byte)8) | (t1 << (byte)4));
            r[(short)((byte)3 * i + (byte)2)] = (byte) (t1 >>  (byte)4);
        }
    }

    //smart card ok, opt ok
    public void polyFromBytes(byte[] a, short[] r)
    {
        for (short i = 0; i < KyberParams.paramsN / 2; i++)
        {
            r[(short)(2 * i)] = (short)((((a[(short)(3 * i + 0)] & 0xFF) >> 0) | ((a[(short)(3 * i + 1)] & 0xFF) << 8)) & 0xFFF);
            r[(short)(2 * i + 1)] = (short)((((a[(short)(3 * i + 1)] & 0xFF) >> 4) | ((a[(short)(3 * i + 2)] & 0xFF) << 4)) & 0xFFF);
        }
    }

    //smart card ok, opt ok
    public void polyFromData(byte[] msg, short[] r)
    {
        short mask;
        for (byte i = 0; i < KyberParams.paramsN / 8; i++)
        {
            for (byte j = 0; j < 8; j++)
            {
                mask = (short)(-1 * (short)(((msg[i] & 0xFF) >> j) & 1));
                r[(short)(8 * i + j)] = (short) (mask & (short) ((KyberParams.paramsQ + 1) / 2));
            }
        }
    }

    //smart card ok, opt ok
    public void polyToMsg(short[] a, byte[] msg)
    {
        short t;
        this.polyConditionalSubQ(a);
        for (byte i = 0; i < (byte)(KyberParams.paramsN / 8); i++)
        {
            msg[i] = 0;
            for (byte j = 0; j < 8; j++)
            {
                t = (short)(((short)((a[(short)(8 * i + j)] << 1) + (KyberParams.paramsQ / 2)) / KyberParams.paramsQ) & 1);
                msg[i] = (byte)(msg[i] | (t << j));
            }
        }
    }

    //Smart card ok, opt ok
    public void getNoisePoly(byte[] seed, byte nonce, byte paramsK, short[] result)
    {
        short l;
        switch (paramsK)
        {
            //this part is already supported for all three kyber
            case 2:
                l = KyberParams.paramsETAK512 * KyberParams.paramsN / 4;
                break;
            default:
                l = KyberParams.paramsETAK768K1024 * KyberParams.paramsN / 4;
        }
        //p = RAM384B_1
        this.generatePRFByteArray(l, seed, nonce, RAM384B_1);
        this.generateCBDPoly(RAM384B_1, paramsK, result);
    }

    //smart card ok, need optimization
    public void generateCBDPoly(byte[] buf, byte paramsK, short[] result)
    {
        //buf = RAM384B_1
        //d = RAM4B_1
        //t = RAM4B_2
        //tempT = RAM4B_3

        short a, b;
        switch (paramsK)
        {
            case 2:
                for (byte i = 0; i < KyberParams.paramsN / 4; i++)
                {
                    //t = Poly.convertByteTo24BitUnsignedInt(Arrays.copyOfRange(buf, (3 * i), buf.length));
                    RAM4B_2[0] = buf[(short)(3*i+2)];
                    RAM4B_2[1] = buf[(short)(3*i+1)];
                    RAM4B_2[2] = buf[(short)(3*i+0)];
                    RAM4B_2[3] = (byte)0x00;

                    //t & 0x00249249
                    RAM4B_1[0] = (byte)(RAM4B_2[0] & 0x24);
                    RAM4B_1[1] = (byte)(RAM4B_2[1] & 0x92);
                    RAM4B_1[2] = (byte)(RAM4B_2[2] & 0x49);
                    RAM4B_1[3] = (byte)0x00;

                    //t >> 1
                    RAM4B_2[3] = (byte)0x00;
                    RAM4B_2[2] = (byte)(((RAM4B_2[2]&0xFF)>>1) | ((RAM4B_2[1]&0xFF)<<7));
                    RAM4B_2[1] = (byte)(((RAM4B_2[1]&0xFF)>>1) | ((RAM4B_2[0]&0xFF)<<7));
                    RAM4B_2[0] = (byte)(((RAM4B_2[0]&0xFF)>>1));

                    //(t >> 1) & 0x00249249
                    RAM4B_3[0] = (byte)(RAM4B_2[0] & 0x24);
                    RAM4B_3[1] = (byte)(RAM4B_2[1] & 0x92);
                    RAM4B_3[2] = (byte)(RAM4B_2[2] & 0x49);
                    RAM4B_3[3] = (byte)0x00;

                    //d = d + (t >> 1) & 0x00249249
                    Arithmetic.sumByteArrays(RAM4B_1,RAM4B_3);

                    //t >> 1
                    RAM4B_2[3] = (byte)0x00;
                    RAM4B_2[2] = (byte)(((RAM4B_2[2]&0xFF)>>1) | ((RAM4B_2[1]&0xFF)<<7));
                    RAM4B_2[1] = (byte)(((RAM4B_2[1]&0xFF)>>1) | ((RAM4B_2[0]&0xFF)<<7));
                    RAM4B_2[0] = (byte)(((RAM4B_2[0]&0xFF)>>1));

                    //(t >> 1) & 0x00249249
                    RAM4B_3[0] = (byte)(RAM4B_2[0] & 0x24);
                    RAM4B_3[1] = (byte)(RAM4B_2[1] & 0x92);
                    RAM4B_3[2] = (byte)(RAM4B_2[2] & 0x49);
                    RAM4B_3[3] = (byte)0x00;

                    //d = d + (t >> 1) & 0x00249249
                    Arithmetic.sumByteArrays(RAM4B_1,RAM4B_3);

                    //for (int j = 0; j < 4; j++) //replaced loop with static 4 assignments
                    //See generateCBDPoly.txt
                    a = (short)(((RAM4B_1[2]&0xFF)>>0) & 0x7);                          //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((RAM4B_1[1]&0xFF)<<5) | ((RAM4B_1[2]&0xFF)>>3)) & 0x7);//3  //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    result[(short)(4 * i + 0)] = (short)(a - b);                  //r[4 * i + j] = (short)(a - b);

                    a = (short)((((RAM4B_1[1]&0xFF)<<2) | ((RAM4B_1[2]&0xFF)>>6)) & 0x7);//6  //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((RAM4B_1[0]&0xFF)<<7) | ((RAM4B_1[1]&0xFF)>>1)) & 0x7);//9  //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    result[(short)(4 * i + 1)] = (short)(a - b);                  //r[4 * i + j] = (short)(a - b);

                    a = (short)((((RAM4B_1[0]&0xFF)<<4) | ((RAM4B_1[1]&0xFF)>>4)) & 0x7);//12 //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((RAM4B_1[0]&0xFF)<<1) | ((RAM4B_1[1]&0xFF)>>7)) & 0x7);//15 //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    result[(short)(4 * i + 2)] = (short)(a - b);                  //r[4 * i + j] = (short)(a - b);

                    a = (short)(((RAM4B_1[0]&0xFF)>>2) & 0x7);//18                      //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)(((RAM4B_1[0]&0xFF)>>5) & 0x7);//21                      //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    result[(short)(4 * i + 3)] = (short)(a - b);                  //r[4 * i + j] = (short)(a - b);
                }
                break;
            default:
                for (byte i = 0; i < KyberParams.paramsN / 8; i++)
                {
                    //t = this.convertByteTo32BitUnsignedInt(Arrays.copyOfRange(buf, (4 * i), buf.length));
                    RAM4B_2[0] = buf[(short)(4*i+3)];
                    RAM4B_2[1] = buf[(short)(4*i+2)];
                    RAM4B_2[2] = buf[(short)(4*i+1)];
                    RAM4B_2[3] = buf[(short)(4*i+0)];

                    //t & 0x55555555
                    RAM4B_1[0] = (byte)(RAM4B_2[0] & 0x55);
                    RAM4B_1[1] = (byte)(RAM4B_2[1] & 0x55);
                    RAM4B_1[2] = (byte)(RAM4B_2[2] & 0x55);
                    RAM4B_1[3] = (byte)(RAM4B_2[3] & 0x55);

                    //t >> 1
                    RAM4B_2[3] = (byte)(((RAM4B_2[3]&0xFF)>>1) | ((RAM4B_2[2]&0xFF)<<7));
                    RAM4B_2[2] = (byte)(((RAM4B_2[2]&0xFF)>>1) | ((RAM4B_2[1]&0xFF)<<7));
                    RAM4B_2[1] = (byte)(((RAM4B_2[1]&0xFF)>>1) | ((RAM4B_2[0]&0xFF)<<7));
                    RAM4B_2[0] = (byte)(((RAM4B_2[0]&0xFF)>>1));

                    //(t >> 1) & 0x55555555
                    RAM4B_3[0] = (byte)(RAM4B_2[0] & 0x55);
                    RAM4B_3[1] = (byte)(RAM4B_2[1] & 0x55);
                    RAM4B_3[2] = (byte)(RAM4B_2[2] & 0x55);
                    RAM4B_3[3] = (byte)(RAM4B_2[3] & 0x55);

                    //d = d + (t >> 1) & 0x55555555
                    Arithmetic.sumByteArrays(RAM4B_1,RAM4B_3);

                    //for (int j = 0; j < 8; j++) //replaced loop with static 8 assignments
                    a = (short)(((RAM4B_1[3]&0xFF)>>0) & 0x3);
                    b = (short)((((RAM4B_1[2]&0xFF)<<6) | ((RAM4B_1[3]&0xFF)>>2)) & 0x3); //2
                    result[(short)(8 * i + 0)] = (short)(a - b);

                    a = (short)((((RAM4B_1[2]&0xFF)<<4) | ((RAM4B_1[3]&0xFF)>>4)) & 0x3); //4
                    b = (short)((((RAM4B_1[2]&0xFF)<<2) | ((RAM4B_1[3]&0xFF)>>6)) & 0x3); //6
                    result[(short)(8 * i + 1)] = (short)(a - b);

                    a = (short)((((RAM4B_1[2]&0xFF)<<0) | ((RAM4B_1[3]&0xFF)>>8)) & 0x3); //8
                    b = (short)((((RAM4B_1[1]&0xFF)<<6) | ((RAM4B_1[2]&0xFF)>>2)) & 0x3); //10
                    result[(short)(8 * i + 2)] = (short)(a - b);

                    a = (short)((((RAM4B_1[1]&0xFF)<<4) | ((RAM4B_1[2]&0xFF)>>4)) & 0x3); //12
                    b = (short)((((RAM4B_1[1]&0xFF)<<2) | ((RAM4B_1[2]&0xFF)>>6)) & 0x3); //14
                    result[(short)(8 * i + 3)] = (short)(a - b);

                    a = (short)((((RAM4B_1[1]&0xFF)<<0) | ((RAM4B_1[2]&0xFF)>>8)) & 0x3); //16
                    b = (short)((((RAM4B_1[0]&0xFF)<<6) | ((RAM4B_1[1]&0xFF)>>2)) & 0x3); //18
                    result[(short)(8 * i + 4)] = (short)(a - b);

                    a = (short)((((RAM4B_1[0]&0xFF)<<4) | ((RAM4B_1[1]&0xFF)>>4)) & 0x3); //20
                    b = (short)((((RAM4B_1[0]&0xFF)<<2) | ((RAM4B_1[1]&0xFF)>>6)) & 0x3); //22
                    result[(short)(8 * i + 5)] = (short)(a - b);

                    a = (short)((((RAM4B_1[0]&0xFF)<<0) | ((RAM4B_1[1]&0xFF)>>8)) & 0x3); //24
                    b = (short)(((RAM4B_1[0]&0xFF)>>2) & 0x3); //26
                    result[(short)(8 * i + 6)] = (short)(a - b);

                    a = (short)(((RAM4B_1[0]&0xFF)>>4) & 0x3); //28
                    b = (short)(((RAM4B_1[0]&0xFF)>>6) & 0x3); //30
                    result[(short)(8 * i + 7)] = (short)(a - b);
                }
        }
    }

    //smart card ok, opt ok
    public void generatePRFByteArray(short l, byte[] key, byte nonce, byte[] result)
    {
        //result = RAM384B_1
        //RAM33B_1 = newKey, static 33 since key is always 32, so newKey = 32 + 1
        Util.arrayCopyNonAtomic(key, (short)0, RAM33B_1, (short)0, (short)32);
        RAM33B_1[32] = nonce;
        Keccak keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength(l);
        keccak.doFinal(RAM33B_1, result);
    }

    // smart card ok, opt ok
    public void polyNTT(short[] r)
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
    }

    //smart card ok
    public short modQMulMont(short a, short b)
    {
        //(long) ((long) a * (long) b)
        Arithmetic.multiplyShorts(a,b, jc);
        return this.montgomeryReduce(jc);
    }

    //smart card ok, optimize jc away
    public short montgomeryReduce(short[] jc)
    {
        //short u = (short) (a * KyberParams.paramsQinv);
        short u = (short)((jc[1] * KyberParams.paramsQinv) & (short)0xFFFF);

        //int t = (int) (u * KyberParams.paramsQ);
        Arithmetic.multiplyShorts(KyberParams.paramsQ,u, multiplied);

        //t = (int) (a - t);
        Arithmetic.subtract(jc,multiplied);

        // t >>= 16;
        return jc[0];
    }

    //smart card ok, opt ok
    public void polyInvNTTMont(short[] r)
    {
        this.invNTT(r);
    }

    //smart card ok, opt ok
    public void invNTT(short[] r)
    {
        short j = 0;
        short k = 0;
        for (short l = 2; l <= 128; l <<= 1)
        {
            for (short start = 0; start < 256; start = (short)(j + l))
            {
                short zeta = nttZetasInv[k];
                k+=1;
                for (j = start; j < (short)(start + l); j++)
                {
                    short t = r[j];
                    r[j] = this.barrettReduce((short)(t + r[(short)(j + l)]));
                    r[(short)(j + l)] = (short)(t - r[(short)(j + l)]);
                    r[(short)(j + l)] = this.modQMulMont(zeta, r[(short)(j + l)]);
                }
            }
        }
        for (j = 0; j < 256; j++)
        {
            r[j] = this.modQMulMont(r[j], nttZetasInv[127]);
        }
    }

    //smart card ok
    public void polyBaseMulMont(short[] polyA, short[] polyB)
    {
        //rx = RAM2S_1
        //ry = RAM2S_2
        for (byte i = 0; i < (KyberParams.paramsN / 4); i++)
        {
            this.baseMultiplier(
                    polyA[(short)(4 * i + 0)], polyA[(short)(4 * i + 1)],
                    polyB[(short)(4 * i + 0)], polyB[(short)(4 * i + 1)],
                    Poly.nttZetas[64 + i]
            , RAM2S_1);
            this.baseMultiplier(
                    polyA[(short)(4 * i + 2)], polyA[(short)(4 * i + 3)],
                    polyB[(short)(4 * i + 2)], polyB[(short)(4 * i + 3)],
                    (short)(-1 * Poly.nttZetas[(short)(64 + i)])
            , RAM2S_2);
            polyA[(short)(4 * i + 0)] = RAM2S_1[0];
            polyA[(short)(4 * i + 1)] = RAM2S_1[1];
            polyA[(short)(4 * i + 2)] = RAM2S_2[0];
            polyA[(short)(4 * i + 3)] = RAM2S_2[1];
        }
    }

    //smart card ok
    public void baseMultiplier(short a0, short a1, short b0, short b1, short zeta, short[] r)
    {
        r[0] = this.modQMulMont(a1, b1);
        r[0] = this.modQMulMont(r[0], zeta);
        r[0] = (short)(r[0] + this.modQMulMont(a0, b0));
        r[1] = this.modQMulMont(a0, b1);
        r[1] = (short)(r[1] + this.modQMulMont(a1, b0));
    }

    //smart card ok, opt ok
    public void polyToMont(short[] polyR)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            //polyR[i] = this.montgomeryReduce((int) (polyR[i] * 1353));
            Arithmetic.multiplyShorts(polyR[i],(short)1353, jc);
            polyR[i] = this.montgomeryReduce(jc);
        }
    }

    //smart card ok, opt ok
    public void polyReduce(short[] r)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            r[i] = this.barrettReduce(r[i]);
        }
    }

    //smart card ok, opt ok
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

    //smart card ok, opt ok
    public void polyConditionalSubQ(short[] r)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            r[i] = this.conditionalSubQ(r[i]);
        }
    }

    //smart card ok, potential issue when a > short max ?, opt ok
    public short conditionalSubQ(short a)
    {
        a = (short)(a - KyberParams.paramsQ);
        a = (short)(a + ((a >> 15) & KyberParams.paramsQ));
        return a;
    }

    //smart card ok, opt ok
    public void polyAdd(short[] polyA, short[] polyB)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            polyA[i] = (short)(polyA[i] + polyB[i]);
        }
    }

    //smart card ok, need opt
    public void polySub(short[] polyA, short[] polyB)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            polyA[i] = (short)(polyA[i] - polyB[i]);
        }
    }

    //smart card ok, opt ok
    public void compressPolyVector(short[] a, byte paramsK, byte[] r)
    {
        this.polyVectorCSubQ(a, paramsK);
        short rr = 0;
        switch (paramsK)
        {
            case 2:
            case 3:
                for (byte i = 0; i < paramsK; i++)
                {
                    for (short j = 0; j < KyberParams.paramsN / 4; j++)
                    {
                        for (byte k = 0; k < 4; k++)
                        {
                            //t[k] = ((long) (((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x3ff);

                            this.arrayCopyNonAtomic(a,(short)(i*384),RAM384S_1,(short)0,(short)384);

                            //((long) (a[i][4 * j + k]) << 10)
                            short shHigh = (short)((RAM384S_1[(short)(4 * j + k)]) >> 6);
                            short shLow = (short)((RAM384S_1[(short)(4 * j + k)]) << 10);

                            //((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2))
                            Arithmetic.add(shHigh, shLow, (short)0, (short)(KyberParams.paramsQ / 2), result);

                            //(((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ))
                            Arithmetic.divide(result[0], result[1], (short)0, KyberParams.paramsQ, result);

                            //((long) (((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x3ff)
                            RAM32S_1[k] = (short)(result[1]&0x3FF);
                        }
                        r[(short)(rr + 0)] = (byte)(RAM32S_1[0] >> 0);
                        r[(short)(rr + 1)] = (byte)((RAM32S_1[0] >> 8) | (RAM32S_1[1] << 2));
                        r[(short)(rr + 2)] = (byte)((RAM32S_1[1] >> 6) | (RAM32S_1[2] << 4));
                        r[(short)(rr + 3)] = (byte)((RAM32S_1[2] >> 4) | (RAM32S_1[3] << 6));
                        r[(short)(rr + 4)] = (byte)((RAM32S_1[3] >> 2));
                        rr+=5;
                    }
                }
                break;
            default:
                short[] t = new short[8];
                for (byte i = 0; i < paramsK; i++)
                {
                    for (int j = 0; j < KyberParams.paramsN / 8; j++)
                    {
                        for (int k = 0; k < 8; k++)
                        {
                            this.arrayCopyNonAtomic(a,(short)(i*384),RAM384S_1,(short)0,(short)384);
                            t[k] = (short)((long) (((long) ((long) (RAM384S_1[8 * j + k]) << 11) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x7ff);
                        }
                        r[rr + 0] = (byte) ((t[0] >> 0));
                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 3));
                        r[rr + 2] = (byte) ((t[1] >> 5) | (t[2] << 6));
                        r[rr + 3] = (byte) ((t[2] >> 2));
                        r[rr + 4] = (byte) ((t[2] >> 10) | (t[3] << 1));
                        r[rr + 5] = (byte) ((t[3] >> 7) | (t[4] << 4));
                        r[rr + 6] = (byte) ((t[4] >> 4) | (t[5] << 7));
                        r[rr + 7] = (byte) ((t[5] >> 1));
                        r[rr + 8] = (byte) ((t[5] >> 9) | (t[6] << 2));
                        r[rr + 9] = (byte) ((t[6] >> 6) | (t[7] << 5));
                        r[rr + 10] = (byte) ((t[7] >> 3));
                        rr+=11;
                    }
                }
        }
    }

    //smart card ok, opt ok
    public void decompressPolyVector(byte[] a, byte paramsK, short[] r)
    {
        //t = RAM32S_1, t is 4 for paramsK = 2 or 3, and t = 8 for paramsK = 4
        short aa = 0;
        switch (paramsK)
        {
            case 2:
            case 3:

                for (byte i = 0; i < paramsK; i++)
                {
                    for (byte j = 0; j < (KyberParams.paramsN / 4); j++)
                    {
                        RAM32S_1[0] = (short)(((a[(short)(aa + 0)] & (short)0xFF) >> 0) | ((a[(short)(aa + 1)] & (short)0xFF) << 8));
                        RAM32S_1[1] = (short)(((a[(short)(aa + 1)] & (short)0xFF) >> 2) | ((a[(short)(aa + 2)] & (short)0xFF) << 6));
                        RAM32S_1[2] = (short)(((a[(short)(aa + 2)] & (short)0xFF) >> 4) | ((a[(short)(aa + 3)] & (short)0xFF) << 4));
                        RAM32S_1[3] = (short)(((a[(short)(aa + 3)] & (short)0xFF) >> 6) | ((a[(short)(aa + 4)] & (short)0xFF) << 2));
                        aa+=5;
                        for (byte k = 0; k < 4; k++)
                        {
                            //(long) (t[k] & 0x3FF) * (long) (KyberParams.paramsQ)
                            Arithmetic.multiplyShorts((short)(RAM32S_1[k] & 0x3FF), KyberParams.paramsQ, multiplied);

                            //((long) (t[k] & 0x3FF) * (long) (KyberParams.paramsQ) + 512)
                            Arithmetic.add(multiplied[0], multiplied[1], (short)0, (short)512, multiplied);

                            //((long) (t[k] & 0x3FF) * (long) (KyberParams.paramsQ) + 512) >> 10
                            short value = (short)((multiplied[0]<<6) | (((multiplied[1]>>8)&(short)0xFF) >> 2));

                            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384S_1, (short)0, (short)384);
                            RAM384S_1[(short)(4 * j + k)] = value;
                            this.arrayCopyNonAtomic(RAM384S_1, (short)0, r, (short)(i * (short)384), (short)384);
                        }
                    }
                }
                break;
            default:
                int[] t = new int[8]; // has to be unsigned..
                for (byte i = 0; i < paramsK; i++)
                {
                    for (int j = 0; j < (KyberParams.paramsN / 8); j++)
                    {
                        t[0] = (((a[aa + 0] & 0xff) >> 0) | ((a[aa + 1] & 0xff) << 8));
                        t[1] = (((a[aa + 1] & 0xff) >> 3) | ((a[aa + 2] & 0xff) << 5));
                        t[2] = (((a[aa + 2] & 0xff) >> 6) | ((a[aa + 3] & 0xff) << 2) | ((a[aa + 4] & 0xff) << 10));
                        t[3] = (((a[aa + 4] & 0xff) >> 1) | ((a[aa + 5] & 0xff) << 7));
                        t[4] = (((a[aa + 5] & 0xff) >> 4) | ((a[aa + 6] & 0xff) << 4));
                        t[5] = (((a[aa + 6] & 0xff) >> 7) | ((a[aa + 7] & 0xff) << 1) | ((a[aa + 8] & 0xff) << 9));
                        t[6] = (((a[aa + 8] & 0xff) >> 2) | ((a[aa + 9] & 0xff) << 6));
                        t[7] = (((a[aa + 9] & 0xff) >> 5) | ((a[aa + 10] & 0xff) << 3));
                        aa+=11;
                        for (int k = 0; k < 8; k++)
                        {
                            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384S_1, (short)0, (short)384);
                            RAM384S_1[8 * j + k] = (short) (((long) (t[k] & 0x7FF) * (long) (KyberParams.paramsQ) + 1024) >> 11);
                            this.arrayCopyNonAtomic(RAM384S_1, (short)0, r, (short)(i * (short)384), (short)384);
                        }
                    }
                }
        }
    }

    //Smart card ok, opt ok
    public void polyVectorToBytes(short[] polyA, byte paramsK, byte[] r)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            this.arrayCopyNonAtomic(polyA, (short)(i * KyberParams.paramsPolyBytes), RAM384S_1, (short)0, KyberParams.paramsPolyBytes);
            this.polyToBytes(RAM384S_1, RAM384B_1);
            Util.arrayCopyNonAtomic(RAM384B_1, (short)0, r, (short)(i * KyberParams.paramsPolyBytes), (short)RAM384B_1.length);
        }
    }

    //smart card ok, opt ok
    public void polyVectorFromBytes(byte[] polyA, byte paramsK, short[] r)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //paramsK is max 4 here
            //max end = 4+1 = 5 * 384 = 1920 - 4*384 = 384 always
            short start = (short)(i * KyberParams.paramsPolyBytes);
            Util.arrayCopyNonAtomic(polyA, start, RAM384B_1, (short)0, (short)384);
            this.polyFromBytes(RAM384B_1, RAM384S_1);
            this.arrayCopyNonAtomic(RAM384S_1, (short)0, r, (short)(i*384), (short)384);
        }
    }

    //smart card ok, opt ok
    //k = 2, r = 384 || 384
    public void polyVectorNTT(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384S_1, (short)0, (short)384);
            this.polyNTT(RAM384S_1);
            this.arrayCopyNonAtomic(RAM384S_1, (short)0, r, (short)(i * (short)384), (short)384);
        }
    }

    //smart card ok, opt ok
    public void polyVectorInvNTTMont(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384S_1, (short)0, (short)384);
            this.polyInvNTTMont(RAM384S_1);
            this.arrayCopyNonAtomic(RAM384S_1, (short)0, r, (short)(i * (short)384), (short)384);
        }
    }

    //smart card ok, opt ok
    public void polyVectorPointWiseAccMont(short[] polyA, short[] polyB, byte paramsK, short[] result)
    {
        short rowSize = 384;
        this.arrayCopyNonAtomic(polyB, (short)0, RAM384S_1, (short)0, rowSize);
        this.arrayCopyNonAtomic(polyA, (short)0, result, (short)0, rowSize);
        this.polyBaseMulMont(result, RAM384S_1);
        for (byte i = 1; i < paramsK; i++)
        {
            this.arrayCopyNonAtomic(polyA, (short)(i*rowSize), RAM384S_2, (short)0, rowSize);
            this.arrayCopyNonAtomic(polyB, (short)(i*rowSize), RAM384S_1, (short)0, rowSize);
            this.polyBaseMulMont(RAM384S_2, RAM384S_1);
            this.polyAdd(result, RAM384S_2);
        }
        this.polyReduce(result);
    }

    ////smart card ok, opt ok
    // k = 2, r = 384 || 384
    public void polyVectorReduce(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384S_1, (short)0, (short)384);
            this.polyReduce(RAM384S_1);
            this.arrayCopyNonAtomic(RAM384S_1, (short)0, r, (short)(i * (short)384), (short)384);
        }
    }

    //smart card ok, opt ok
    public void polyVectorCSubQ(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            this.arrayCopyNonAtomic(r,(short)(i*384),RAM384S_1,(short)0,(short)384);
            this.polyConditionalSubQ(RAM384S_1);
            this.arrayCopyNonAtomic(RAM384S_1,(short)0,r,(short)(i*384),(short)384);
        }
    }

    //smart card ok, opt ok
    public void polyVectorAdd(short[] polyA, short[] polyB, byte paramsK)
    {
        short rowSize = 384;
        for (byte i = 0; i < paramsK; i++)
        {
            for (short j = 0; j < rowSize; j++)
            {
                polyA[(short)((i * rowSize) + j)] += polyB[(short)((i * rowSize) + j)];
            }
        }
    }
}