package Kyber.Implementation.SmartCard;

public class JCInteger
{
    private static final short BYTE_SIZE = 8;
    private static final short SHORT_SIZE = 16;
    private static final short INTEGER_SIZE = 32;

    private static final short HIGH = 0;
    private static final short LOW = 1;

    private final short[] values;

    private JCInteger() {
        // TODO this should be backed by an array in RAM, using JCSystem.makeTransientByteArray()
        // using either JCSystem.CLEAR_ON_RESET or JCSystem.CLEAR_ON_DESELECT
        values = new short[(short) 2];
    }

    public static JCInteger createInstance() {
        return new JCInteger();
    }

    public JCInteger assign(final JCInteger rightHandOperand) {
        values[HIGH] = rightHandOperand.values[HIGH];
        values[LOW] = rightHandOperand.values[LOW];
        return this;
    }

    public JCInteger assign(final short high, final short low) {
        values[HIGH] = high;
        values[LOW] = low;
        return this;
    }

    public JCInteger assignSigned(final short signedValue) {
        if (signedValue >= 0) {
            values[HIGH] = (short) 0x0000;
        } else {
            values[HIGH] = (short) 0xFFFF;
        }
        values[LOW] = signedValue;
        return this;
    }

    public JCInteger assignUnsigned(final short unsignedValue) {
        values[HIGH] = (short) 0x0000;
        values[LOW] = unsignedValue;
        return this;
    }

    public short getHigh() {
        // no pun intended
        return values[HIGH];
    }

    public short getLow() {
        return values[LOW];
    }

    public short[] getBackingShortArray() {
        return values;
    }

    public JCInteger negate() {

        // basically invert, then increase, note that -Integer.MIN_VALUE = Integer.MIN_VALUE (as it is in Java)
        values[HIGH] = (short)~values[HIGH];
        values[LOW] = (short)~values[LOW];
        increment();
        return this;
    }

    public JCInteger increment() {
        values[LOW]++;
        if (values[LOW] == 0) {
            values[HIGH]++;
        }
        return this;
    }

    public JCInteger decrement() {
        values[LOW]--;
        if (values[LOW] == -1) {
            values[HIGH]--;
        }
        return this;
    }

    public JCInteger add(final JCInteger y) {
        addUnsignedLow(y.values[LOW]);
        values[HIGH] += y.values[HIGH];
        return this;
    }

    public JCInteger subtract(final JCInteger y) {
        // subtracts by adding the negated i
        // negation is identical to invert + increase
        // however the increase is performed to the result of adding the inverted value

        // invert
        final short xlInv = (short) ~y.values[LOW];
        final short xhInv = (short) ~y.values[HIGH];

        // add
        addUnsignedLow(xlInv);
        values[HIGH] += xhInv;

        // increase
        increment();
        return this;
    }

    public JCInteger multiply(JCInteger y) {
        // uses the fact that:
        // x * y =
        // (x1 * 2 ^ 16 + x0) * (y1 * 2 ^ 16 + y0) =
        // (x1 * y1 * 2 ^ 32) + x1 * y0 * 2 ^ 16 + x0 * y1 * 2 ^ 16 + x0 * y0 =
        // x1 * y0 * 2 ^ 16 + x0 * y1 * 2 ^ 16 + x0 * y0 (because anything * 2 ^ 32 overflows all the bits) =
        // x1 * y0 * 2 ^ 16 + x0 * y1 * 2 ^ 16 + z1 | z0 (where z1 = high 16 bits of x0 * y* and z0 is the low part) =
        // r1 | r0 where r1 = x1 * y0 + x0 * y1 + z1 and r0 = z0
        // r1 is only 16 bits so x1 * y0 and x0 * y0 may overflow, as may the additions, hopefully leaving the sign
        // bit correctly set

        boolean xPositive = this.isPositive();
        if (!xPositive) {
            this.negate();
        }

        final short xh = this.values[HIGH];
        final short xl = this.values[LOW];

        short yh = y.values[HIGH];
        short yl = y.values[LOW];

        // --- if signed then negate y ---
        final boolean yPositive;
        if ((yh & (short)0x8000) == 0) {
            yPositive = true;
        } else {
            // negation (complement then increase)
            yh = (short) ~yh;
            yl = (short) ~yl;
            yl++;
            if (yl == 0) {
                yh++;
            }
            yPositive = false;
        }

        // calculates z1 and z0 and stores it in the current values
        multiplyUnsigned(xl, yl, values);

        // perform the calculation for the high parts
        values[HIGH] += (short) (xh * yl + xl * yh);

        // make sure we return a correctly signed value
        if ((xPositive && !yPositive) || (!xPositive && yPositive)) {
            this.negate();
        }

        return this;
    }

    public JCInteger divide(JCInteger y)
    {

        // --- pre-calculations on y ---

        // put y in yh and yl
        short yh = y.values[HIGH];
        short yl = y.values[LOW];

        if (yh == 0 && yl == 0) {
            // division by zero
            throw new ArithmeticException();
        }

        final boolean yPositive;
        if ((yh & (short)0x8000) == 0) {
            yPositive = true;
        } else {
            // negation (complement then increase)
            yh = (short) ~yh;
            yl = (short) ~yl;
            yl++;
            if (yl == 0) {
                yh++;
            }
            yPositive = false;
        }

        final short divisorSize = (short) (INTEGER_SIZE - numberOfLeadingZeros(yh, yl));

        // --- pre-calculations on x ---

        final boolean xPositive = this.isPositive();
        if (!xPositive) {
            this.negate();
        }
        final short dividentSize = (short) (INTEGER_SIZE - numberOfLeadingZeros());

        // --- setup the maximum number of shifts ---

        final short maxShifts = (short) (dividentSize - divisorSize);

        // --- slightly superfluous check if divisor is higher than dividend ---

        if (maxShifts < 0) {
            // return 0, no division can be performed
            values[HIGH] = 0;
            values[LOW] = 0;
            return this;
        }

        // --- shift divisor left until the highest bit is aligned with the highest bit of the dividend ---

        if (maxShifts <= JCInteger.SHORT_SIZE) {
            yh = (short) (((yl & 0xFFFF) >>> (SHORT_SIZE - maxShifts)) | (yh << maxShifts));
            yl <<= maxShifts;
        } else {
            yh = (short) (yl << (maxShifts - SHORT_SIZE));
            yl = 0;
        }

        short rh = 0, rl = 0;
        for (short i = maxShifts; i >= 0; i--) {
            final short xho = values[HIGH];
            final short xlo = values[LOW];

            // --- subtract (add complement and increment does the job) ---

            // add complement
            addUnsignedLow((short) ~yl);
            values[HIGH] += (short) ~yh;

            // increase to create subtraction
            increment();

            if (isPositive()) {
                // --- we have subtracted y * 2 ^ n, so include 2 ^ n to the result ---
                if (i >= SHORT_SIZE) {
                    rh |= 1 << (i - SHORT_SIZE);
                } else {
                    rl |= 1 << i;
                }
            } else {
                // --- we could not subtract, so restore ---
                values[HIGH] = xho;
                values[LOW] = xlo;
            }

            // --- shift right by 1 ---
            // first do low shift as high shift changes value
            yl = (short) ((yh << (JCInteger.SHORT_SIZE - 1)) | ((yl & 0xFFFF) >>> 1));
            yh = (short) ((yh & 0xFFFF) >>> 1);
        }

        values[HIGH] = rh;
        values[LOW] = rl;

        // make sure we return a correctly signed value (may mess up sign bit on overflows?)
        if ((xPositive && !yPositive) || (!xPositive && yPositive)) {
            this.negate();
        }

        return this;
    }

    public JCInteger remainder(JCInteger y) {

        // --- pre-calculations on y ---

        // put y in yh and yl
        short yh = y.values[HIGH];
        short yl = y.values[LOW];

        if (yh == 0 && yl == 0) {
            // division by zero
            throw new ArithmeticException();
        }

        if ((yh & 0x8000) != 0) {
            // negation (complement then increase)
            yh = (short) ~yh;
            yl = (short) ~yl;
            yl++;
            if (yl == 0) {
                yh++;
            }
        }

        final short divisorSize = (short) (INTEGER_SIZE - numberOfLeadingZeros(yh, yl));

        // --- pre-calculations on x ---

        final boolean xPositive = this.isPositive();
        if (!xPositive) {
            this.negate();
        }
        final short dividentSize = (short) (INTEGER_SIZE - numberOfLeadingZeros());

        // --- setup the maximum number of shifts ---

        final short maxShifts = (short) (dividentSize - divisorSize);

        // --- slightly superfluous check if divisor is higher than dividend ---

        if (maxShifts < 0) {
            if (!xPositive) {
                return this.negate();
            }
            return this;
        }

        // --- shift divisor left until the highest bit is aligned with the highest bit of the dividend ---

        if (maxShifts <= JCInteger.SHORT_SIZE) {
            yh = (short) (((yl & 0xFFFF) >>> (SHORT_SIZE - maxShifts)) | (yh << maxShifts));
            yl <<= maxShifts;
        } else {
            yh = (short) (yl << (maxShifts - SHORT_SIZE));
            yl = 0;
        }

        for (short i = maxShifts; i >= 0; i--) {
            final short xho = values[HIGH];
            final short xlo = values[LOW];

            // --- subtract (add complement and increment does the job) ---

            // add complement
            addUnsignedLow((short) ~yl);
            values[HIGH] += (short) ~yh;

            // increase to create subtraction
            increment();

            if (!isPositive()) {
                values[HIGH] = xho;
                values[LOW] = xlo;
            }

            // --- shift right by 1 ---
            // first do low shift as high shift changes value
            yl = (short) ((yh << (JCInteger.SHORT_SIZE - 1)) | ((yl & 0xFFFF) >>> 1));
            yh = (short) ((yh & 0xFFFF) >>> 1);
        }

        if (!xPositive) {
            negate();
        }

        return this;
    }

    public JCInteger leftShift(short shiftDistance) {
        shiftDistance = (short) (shiftDistance & 0x1F);
        if (shiftDistance == 0) {
            return this;
        }

        final short low = values[LOW];
        final short high = values[HIGH];

        // TODO test if we can do without if on Java Card (is integer value calculated? cannot really be.
        if (shiftDistance < SHORT_SIZE) {
            values[HIGH] = (short) (((low & 0xFFFF) >>> (SHORT_SIZE - shiftDistance)) | (high << shiftDistance));
            values[LOW] <<= shiftDistance;
        } else {
            values[HIGH] = (short) (low << (shiftDistance - SHORT_SIZE));
            values[LOW] = 0;
        }

        return this;
    }

    public JCInteger signedRightShift(short shiftDistance) {
        shiftDistance = (short) (shiftDistance & 0x1F);
        if (shiftDistance == 0) {
            return this;
        }

        final short low = values[LOW];
        final short high = values[HIGH];

        if (shiftDistance < SHORT_SIZE) {
            values[HIGH] = (short) (high >>> shiftDistance);
            values[LOW] = (short) ((high << (SHORT_SIZE - shiftDistance)) | ((low & 0xFFFF) >>> shiftDistance));
        } else {
            if ((high & 0x8000) == 0) {
                values[HIGH] = 0;
                values[LOW] = (short) ((high & 0xFFFF) >>> (shiftDistance - SHORT_SIZE));
            } else {
                values[HIGH] = (short) 0xFFFF;
                values[LOW] = (short) (high >>> (shiftDistance - SHORT_SIZE));
            }
        }

        return this;
    }

    public JCInteger unsignedRightShift(short shiftDistance) {
        shiftDistance = (short) (shiftDistance & 0x1F);
        if (shiftDistance == 0) {
            return this;
        }

        final short low = values[LOW];
        final short high = values[HIGH];

        if (shiftDistance < SHORT_SIZE) {
            values[HIGH] = (short) ((high & 0xFFFF) >>> shiftDistance);
            values[LOW] = (short) ((high << (SHORT_SIZE - shiftDistance)) | ((low & 0xFFFF) >>> shiftDistance));
        } else {
            values[HIGH] = 0;
            values[LOW] = (short) ((high & 0xFFFF) >>> (shiftDistance - SHORT_SIZE));
        }

        return this;
    }

    public JCInteger complement() {
        this.values[HIGH] = (short) ~this.values[HIGH];
        this.values[LOW] = (short) ~this.values[LOW];
        return this;
    }

    public JCInteger xor(final JCInteger y) {
        this.values[HIGH] ^= y.values[HIGH];
        this.values[LOW] ^= y.values[LOW];
        return this;
    }

    public JCInteger and(final JCInteger y) {
        this.values[HIGH] &= y.values[HIGH];
        this.values[LOW] &= y.values[LOW];
        return this;
    }

    public JCInteger or(final JCInteger y) {
        this.values[HIGH] |= y.values[HIGH];
        this.values[LOW] |= y.values[LOW];
        return this;
    }

    public short signum() {
        if (values[HIGH] == 0 && values[LOW] == 0) {
            return 0;
        }

        // get sign bit (>>> 15) negate, -1 for neg, 0 for pos, then times 2 (<< 2) which leaves -2 for neg 0 for pos
        // and finally add 1, to get the result -1 or 1 for negative and positive, respectively
        return (short) ((-((values[HIGH] >>> 15) & 1) * 2) + 1);
    }

    public short numberOfLeadingZeros() {
        short t = values[HIGH];

        if (t != 0) {
            for (short i = 0; i < SHORT_SIZE; i++) {
                if (t < 0) {
                    return i;
                }
                t <<= 1;
            }
        }

        t = values[LOW];

        if (t != 0) {
            for (short i = SHORT_SIZE; i < INTEGER_SIZE; i++) {
                if (t < 0) {
                    return i;
                }
                t <<= 1;
            }
        }

        return INTEGER_SIZE;
    }

    public short compareTo(JCInteger anotherInteger) {
        final short xh = values[HIGH];
        final short yh = anotherInteger.values[HIGH];

        if (xh < yh) {
            return -1;
        } else if (xh > yh) {
            return 1;
        }

        // --- xh == yh ---

        final short xl = values[LOW];
        final short yl = anotherInteger.values[LOW];

        // TODO think of better way than four ifs
        if (xl < 0 && yl >= 0) {
            return 1;
        } else if (xl >= 0 && yl < 0) {
            return -1;
        } else if (xl > yl) {
            return 1;
        } else if (xl < yl) {
            return -1;
        }

        return 0;
    }

    public boolean equals(Object obj) {

        if (!(obj instanceof JCInteger)) {
            return false;
        }

        final JCInteger otherInt = (JCInteger) obj;
        return values[HIGH] == otherInt.values[HIGH]
                && values[LOW] == otherInt.values[LOW];
    }

    public short encode(final byte[] bArray, short bOff) {
        // use javacard.framework.Util.setShort() instead
        bArray[bOff++] = (byte) (values[HIGH] >>> BYTE_SIZE);
        bArray[bOff++] = (byte) (values[HIGH] & 0xFF);
        bArray[bOff++] = (byte) (values[LOW] >>> BYTE_SIZE);
        bArray[bOff++] = (byte) (values[LOW] & 0xFF);
        return bOff;
    }

    public JCInteger decode(final byte[] bArray, short bOff) {
        values[HIGH] = (short) ((bArray[bOff++] << BYTE_SIZE) | (bArray[bOff++] & 0xFF));
        values[LOW] = (short) ((bArray[bOff++] << BYTE_SIZE) | (bArray[bOff++] & 0xFF));
        return this;
    }

    private boolean isPositive() {
        return (values[HIGH] & (short)0x8000) == 0;
    }

    private void addUnsignedLow(final short yl) {
        final short xl = values[LOW];
        values[HIGH] += carryOnUnsignedAddition(xl, yl);
        values[LOW] = (short) (xl + yl);
    }

    private static short carryOnUnsignedAddition(final short x, final short y) {
        // implementation without any conditionals on the highest bits of x, y and r = x + y
        final short r = (short) (x + y);
        // uses only the sign bit on the variables including the result to see if carry will happen
        return (short) ((((x & y) | (x & ~y & ~r) | (~x & y & ~r)) >>> 15) & 1);
    }

    private static short[] multiplyUnsigned(short x, short y, short[] r) {

        // uses the fact that:
        // x * y =
        // (x1 * 2 ^ 8 + x0) * (y1 * 2 ^ 8 + y0) =
        // (x1 * y1 * 2 ^ 16) + x1 * y0 * 2 ^ 8 + x0 * y1 * 2 ^ 8 + x0 * y0

        final short x1 = (short) ((x >>> BYTE_SIZE) & 0xFF);
        final short x0 = (short) (x & 0xFF);

        final short y1 = (short) ((y >>> BYTE_SIZE) & 0xFF);
        final short y0 = (short) (y & 0xFF);

        // TODO check uppiest bit of rh and rl

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

        r[HIGH] = rh;
        r[LOW] = rl;
        return r;
    }

    private static short numberOfLeadingZeros(short ih, short il) {

        if (ih != 0) {
            for (short i = 0; i < SHORT_SIZE; i++) {
                if (ih < 0) {
                    return i;
                }
                ih <<= 1;
            }
        }

        if (il != 0) {
            for (short i = SHORT_SIZE; i < INTEGER_SIZE; i++) {
                if (il < 0) {
                    return i;
                }
                il <<= 1;
            }
        }

        return INTEGER_SIZE;
    }
}