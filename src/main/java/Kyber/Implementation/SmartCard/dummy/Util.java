package Kyber.Implementation.SmartCard.dummy;

import java.util.Arrays;

//Dummy Util for smart card code
public class Util
{
    public static void arrayFillNonAtomic(byte[] bc, short i, short i1, byte b)
    {
        Arrays.fill(bc, (byte)0x00);
    }

    public static void arrayCopyNonAtomic(byte[] st, short i, byte[] bc, short i1, short wordl)
    {
        System.arraycopy(st,i,bc,i1,wordl);
    }
}