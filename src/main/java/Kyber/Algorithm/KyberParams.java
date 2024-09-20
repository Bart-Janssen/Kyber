package Kyber.Algorithm;

public class KyberParams
{
    public final static short paramsQinv = (short)62209;
    public final static byte paramsETAK512 = 3;
    public final static byte paramsETAK768K1024 = 2;
    public final static byte KyberSSBytes = 32;
    public final static short paramsN = 256;
    public final static short paramsQ = 3329;
    public final static byte paramsSymBytes = 32;
    public final static short paramsPolyBytes = 384;
    public final static short paramsPolyCompressedBytesK768 = 128;
    public final static short paramsPolyCompressedBytesK1024 = 160;
    public final static short paramsPolyvecCompressedBytesK512 = 2 * 320;
    public final static short paramsPolyvecCompressedBytesK768 = 3 * 320;
    public final static short paramsPolyvecCompressedBytesK1024 = 4 * 352;

    public final static int paramsIndcpaSecretKeyBytesK1024 = 4 * paramsPolyBytes;

    public final static int paramsIndcpaSecretKeyBytesK768 = 3 * paramsPolyBytes;
    public final static int paramsPolyvecBytesK1024 = 4 * paramsPolyBytes;

    public final static short paramsPolyvecBytesK512 = 2 * paramsPolyBytes;
    public final static int paramsPolyvecBytesK768 = 3 * paramsPolyBytes;
    public final static int paramsIndcpaPublicKeyBytesK768 = paramsPolyvecBytesK768 + paramsSymBytes;
    public final static int paramsIndcpaPublicKeyBytesK1024 = paramsPolyvecBytesK1024 + paramsSymBytes;

    public final static short Kyber512SKBytes = paramsPolyvecBytesK512 + ((paramsPolyvecBytesK512 + paramsSymBytes) + 2 * paramsSymBytes);
    public final static int Kyber768SKBytes = paramsPolyvecBytesK768 + ((paramsPolyvecBytesK768 + paramsSymBytes) + 2 * paramsSymBytes);
    public final static int Kyber1024SKBytes = paramsPolyvecBytesK1024 + ((paramsPolyvecBytesK1024 + paramsSymBytes) + 2 * paramsSymBytes);

    public final static short paramsIndcpaSecretKeyBytesK512 = 2 * paramsPolyBytes;
    public final static short paramsIndcpaPublicKeyBytesK512 = paramsPolyvecBytesK512 + paramsSymBytes;
}