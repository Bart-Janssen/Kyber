package Kyber.Implementation.SmartCard.dummy;

import java.util.Arrays;

//Dummy Util for smart card code
public class Util
{
    public static void arrayFillNonAtomic(byte[] bc, short i, short i1, byte b)
    {
        Arrays.fill(bc, (byte)0x00);
    }

    public static void arrayCopyNonAtomic(byte[] src, short srcIndex, byte[] dst, short dstIndex, short length)
    {
        System.arraycopy(src,srcIndex,dst,dstIndex,length);
    }
}