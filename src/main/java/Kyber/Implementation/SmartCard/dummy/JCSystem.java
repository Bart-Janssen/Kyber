package Kyber.Implementation.SmartCard.dummy;

//Dummy JCSystem for smart card code
public class JCSystem
{
    public static final byte CLEAR_ON_DESELECT = 1;

    public static byte[] makeTransientByteArray(final short BYTES, byte i)
    {
        return new byte[BYTES];
    }
    public static short[] makeTransientShortArray(final short BYTES, byte i)
    {
        return new short[BYTES];
    }
}