package Kyber.Models;

public class KyberParams
{
    public final static short paramsQinv = (short)62209;
    public final static byte paramsETAK512 = (byte)3;
    public final static byte paramsETAK768K1024 = (byte)2;
    public final static byte KyberSSBytes = (byte)32;
    public final static short paramsN = (short)256;
    public final static short paramsQ = (short)3329;
    public final static byte paramsSymBytes = (byte)32;
    public final static short paramsPolyBytes = (short)384;
    public final static short paramsPolyCompressedBytesK768 = (short)128;
    public final static short paramsPolyCompressedBytesK1024 = (short)160;
    public final static short paramsPolyvecCompressedBytesK512 = (short)640;//2 * 320
    public final static short paramsPolyvecCompressedBytesK768 = (short)960;//3 * 320
    public final static short paramsPolyvecCompressedBytesK1024 = (short)1408;//4 * 352
    public final static short paramsIndcpaSecretKeyBytesK1024 = (short)1536;//4 * paramsPolyBytes
    public final static short paramsIndcpaSecretKeyBytesK768 = (short)1152;//3 * paramsPolyBytes
    public final static short paramsPolyvecBytesK1024 = (short)1536;//4 * paramsPolyBytes
    public final static short paramsPolyvecBytesK512 = (short)768;//2 * paramsPolyBytes;
    public final static short paramsPolyvecBytesK768 = (short)1152;//3 * paramsPolyBytes
    public final static short paramsIndcpaPublicKeyBytesK768 = (short)1184;//paramsPolyvecBytesK768 + paramsSymBytes;
    public final static short paramsIndcpaPublicKeyBytesK1024 = (short)1568;//paramsPolyvecBytesK1024 + paramsSymBytes;
    public final static short Kyber512SKBytes = (short)1632;//paramsPolyvecBytesK512 + ((paramsPolyvecBytesK512 + paramsSymBytes) + 2 * paramsSymBytes);
    public final static short Kyber768SKBytes = (short)2400;//paramsPolyvecBytesK768 + ((paramsPolyvecBytesK768 + paramsSymBytes) + 2 * paramsSymBytes);
    public final static short Kyber1024SKBytes = (short)3168;//paramsPolyvecBytesK1024 + ((paramsPolyvecBytesK1024 + paramsSymBytes) + 2 * paramsSymBytes);
    public final static short paramsIndcpaSecretKeyBytesK512 = (short)768;//2 * paramsPolyBytes;
    public final static short paramsIndcpaPublicKeyBytesK512 = (short)800;//paramsPolyvecBytesK512 + paramsSymBytes;
}