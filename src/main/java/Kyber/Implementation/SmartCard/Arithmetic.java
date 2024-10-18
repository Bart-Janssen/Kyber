package Kyber.Implementation.SmartCard;

public class Arithmetic
{
    public static void sumByteArrays(byte[] x, byte[] y)
    {
        short carry = 0;
        for (byte i = 2; i >= 0; i--)
        {
            short temp = (short)((x[i]&0xFF) + (y[i]&0xFF) + carry);
            x[i] = (byte)(temp&0xFF);
            carry = (short)(temp>>8);
        }
    }

    public static void subtract(short[] a, short[] b)
    {
        // subtracts by adding the negated i
        // negation is identical to invert + increase
        // however the increase is performed to the result of adding the inverted value

        // invert
        final short xlInv = (short) ~b[1];
        final short xhInv = (short) ~b[0];

        // add
        final short xl = a[1];
        a[0] += carryOnUnsignedAddition(xl, xlInv);
        a[1] = (short)(xl + xlInv);
        a[0] += xhInv;

        // increase
        a[1]++;
        if (a[1] == 0) a[0]++;
    }

    public static void multiplyShorts(short a, short b, short[] multiplied)
    {
        // uses the fact that:
        // x * y =
        // (x1 * 2 ^ 16 + x0) * (y1 * 2 ^ 16 + y0) =
        // (x1 * y1 * 2 ^ 32) + x1 * y0 * 2 ^ 16 + x0 * y1 * 2 ^ 16 + x0 * y0 =
        // x1 * y0 * 2 ^ 16 + x0 * y1 * 2 ^ 16 + x0 * y0 (because anything * 2 ^ 32 overflows all the bits) =
        // x1 * y0 * 2 ^ 16 + x0 * y1 * 2 ^ 16 + z1 | z0 (where z1 = high 16 bits of x0 * y* and z0 is the low part) =
        // r1 | r0 where r1 = x1 * y0 + x0 * y1 + z1 and r0 = z0
        // r1 is only 16 bits so x1 * y0 and x0 * y0 may overflow, as may the additions, hopefully leaving the sign
        // bit correctly set
        short aHigh = (a >= 0) ? (short)0x0000 : (short) 0xFFFF;
        short aLow = a;
        short bHigh = (b >= 0) ? (short)0x0000 : (short) 0xFFFF;
        short bLow = b;

        boolean xPositive = (aHigh & (short)0x8000) == 0;
        if (!xPositive)
        {
            aHigh = (short)~aHigh;
            aLow = (short)~aLow;
            aLow++;
            if (aLow == 0) aHigh++;
        }

        final short xh = aHigh;
        final short xl = aLow;

        // --- if signed then negate y ---
        final boolean yPositive = (bHigh & (short)0x8000) == 0;
        if (!yPositive)
        {
            // negation (complement then increase)
            bHigh = (short)~bHigh;
            bLow = (short)~bLow;
            bLow++;
            if (bLow == 0) bHigh++;
        }

        // calculates z1 and z0 and stores it in the current values
        multiplyUnsigned(xl, bLow, multiplied);

        aHigh = multiplied[0];
        aLow = multiplied[1];

        // perform the calculation for the high parts
        aHigh += (short)(xh * bLow + xl * bHigh);

        // make sure we return a correctly signed value
        if ((xPositive && !yPositive) || (!xPositive && yPositive))
        {
            aHigh = (short)~aHigh;
            aLow = (short)~aLow;
            aLow++;
            if (aLow == 0) aHigh++;
        }
        multiplied[0] = aHigh;
        multiplied[1] = aLow;
    }

    private static void multiplyUnsigned(short x, short y, short[] r)
    {
        // uses the fact that:
        // x * y =
        // (x1 * 2 ^ 8 + x0) * (y1 * 2 ^ 8 + y0) =
        // (x1 * y1 * 2 ^ 16) + x1 * y0 * 2 ^ 8 + x0 * y1 * 2 ^ 8 + x0 * y0
        final short x1 = (short) ((x >>> 8) & 0xFF);
        final short x0 = (short) (x & 0xFF);

        final short y1 = (short) ((y >>> 8) & 0xFF);
        final short y0 = (short) (y & 0xFF);

        // calculate z2 * 2 ^ (2 * 8) = x1 * y1 * 2 ^ (2 * 8) = x1 * y1 << 16,
        // store it as partial result in rh
        short rh = (short) (x1 * y1);

        // calculate z0 = x0 * y0
        short rl = (short) (x0 * y0);

        short toAdd, result;

        // calculate x1 * y0* 2 ^ 8
        short x1y0 = (short) (x1 * y0);
        rh += (x1y0 >>> 8) & 0xFF;
        toAdd = (short) ((x1y0 << 8) & (short)0xFF00);
        result = (short) (rl + toAdd);
        rh += carryOnUnsignedAddition(rl, toAdd);
        rl = result;

        // calculate x0 * y1* 2 ^ 8
        short x0y1 = (short) (x0 * y1);
        rh += (x0y1 >>> 8) & 0xFF;
        toAdd = (short) ((x0y1 << 8) & (short)0xFF00);
        result = (short) (rl + toAdd);
        rh += carryOnUnsignedAddition(rl, toAdd);
        rl = result;

        r[0] = rh;
        r[1] = rl;
    }

    private static short carryOnUnsignedAddition(final short x, final short y)
    {
        // implementation without any conditionals on the highest bits of x, y and r = x + y
        final short r = (short) (x + y);
        // uses only the sign bit on the variables including the result to see if carry will happen
        return (short) ((((x & y) | (x & ~y & ~r) | (~x & y & ~r)) >>> 15) & 1);
    }
}