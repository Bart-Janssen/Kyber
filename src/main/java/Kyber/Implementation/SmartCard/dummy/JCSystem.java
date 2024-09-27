package Kyber.Implementation.SmartCard.dummy;

//Dummy JCSystem for smart card code
public class JCSystem
{
    public static final int CLEAR_ON_DESELECT = 1;

    public static byte[] makeTransientByteArray(final short BYTES, int i)
    {
        return new byte[BYTES];
    }
}