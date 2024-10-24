package Kyber.Implementation.SmartCard;

public class Arithmetic
{
    public static void sumByteArrays(byte[] x, byte[] y)
    {
        short carry = 0;
        for (byte i = (byte)(x.length-1); i >= 0; i--)
        {
            short temp = (short)((x[i]&0xFF) + (y[i]&0xFF) + carry);
            x[i] = (byte)(temp&0xFF);
            carry = (short)(temp>>8);
        }
    }

    public static void divide(short aHigh, short aLow, short bHigh, short bLow, short[] result)
    {
        // --- pre-calculations on y ---

        // put y in yh and yl
        short yh = bHigh;
        short yl = bLow;

        // division by zero
        if (yh == 0 && yl == 0) throw new ArithmeticException();

        final boolean yPositive;
        if ((yh & (short)0x8000) == 0)
        {
            yPositive = true;
        }
        else
        {
            // negation (complement then increase)
            yh = (short)~yh;
            yl = (short)~yl;
            yl++;
            if (yl == 0) yh++;
            yPositive = false;
        }

        final short divisorSize = (short)(32 - numberOfLeadingZeros(yh, yl));

        // --- pre-calculations on x ---

        final boolean xPositive = (aHigh & (short)0x8000) == 0;
        if (!xPositive)
        {
            aHigh = (short)~aHigh;
            aLow = (short)~aLow;
            aLow++;
            if (aLow == 0) aHigh++;
        }
        final short dividentSize = (short)(32 - numberOfLeadingZeros(aHigh, aLow));

        // --- setup the maximum number of shifts ---

        final short maxShifts = (short)(dividentSize - divisorSize);

        // --- slightly superfluous check if divisor is higher than dividend ---

        if (maxShifts < 0)
        {
            // return 0, no division can be performed
            aHigh = 0;
            aLow = 0;
            result[0] = aHigh;
            result[1] = aLow;
            return;
        }

        // --- shift divisor left until the highest bit is aligned with the highest bit of the dividend ---

        if (maxShifts <= 16)
        {
            yh = (short)(((yl & (short)0xFFFF) >>> (16 - maxShifts)) | (yh << maxShifts));
            yl <<= maxShifts;
        }
        else
        {
            yh = (short)(yl << (maxShifts - 16));
            yl = 0;
        }

        short rh = 0, rl = 0;
        for (short i = maxShifts; i >= 0; i--)
        {
            final short xho = aHigh;
            final short xlo = aLow;

            // --- subtract (add complement and increment does the job) ---

            // add complement
            final short xl = aLow;
            aHigh += carryOnUnsignedAddition(xl, (short)~yl);
            aLow = (short)(xl + (short)~yl);
            aHigh += (short)~yh;

            // increase to create subtraction
            aLow++;
            if (aLow == 0) aHigh++;

            if ((aHigh & (short)0x8000) == 0)
            {
                // --- we have subtracted y * 2 ^ n, so include 2 ^ n to the result ---
                if (i >= 16) rh |= 1 << (i - 16);
                else rl |= 1 << i;
            }
            else
            {
                // --- we could not subtract, so restore ---
                aHigh = xho;
                aLow = xlo;
            }

            // --- shift right by 1 ---
            // first do low shift as high shift changes value
            yl = (short)((yh << (16 - 1)) | ((short)((yl & (short)0xFFFF) >> 1) & (short)0x7FFF));
            yh = (short)((yh & (short)0xFFFF) >>> 1);
        }

        aHigh = rh;
        aLow = rl;

        // make sure we return a correctly signed value (may mess up sign bit on overflows?)
        if ((xPositive && !yPositive) || (!xPositive && yPositive))
        {
            aHigh = (short)~aHigh;
            aLow = (short)~aLow;
            aLow++;
            if (aLow == 0) aHigh++;
        }
        result[0] = aHigh;
        result[1] = aLow;
    }

    private static short numberOfLeadingZeros(short ih, short il) {

        if (ih != 0)
        {
            for (short i = 0; i < 16; i++)
            {
                if (ih < 0)  return i;
                ih <<= 1;
            }
        }
        if (il != 0)
        {
            for (short i = 16; i < 32; i++)
            {
                if (il < 0)  return i;
                il <<= 1;
            }
        }
        return 32;
    }

    public static void add(short aHigh, short aLow, short bHigh, short bLow, short[] result)
    {
        final short xl = aLow;
        aHigh += carryOnUnsignedAddition(xl, bLow);
        aLow = (short) (xl + bLow);
        aHigh += bHigh;
        result[0] = aHigh;
        result[1] = aLow;
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