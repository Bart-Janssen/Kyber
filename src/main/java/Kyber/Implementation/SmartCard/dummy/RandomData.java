package Kyber.Implementation.SmartCard.dummy;

import java.security.SecureRandom;

//Dummy RandomData for smart card code
public class RandomData
{
    public static byte ALG_TRNG = 0x00;
    public static class OneShot
    {
        public static OneShot open(byte algorithm)
        {
            return new OneShot();
        }

        public void nextBytes(byte[] rnd, short offset, short length) throws Exception
        {
            SecureRandom.getInstanceStrong().nextBytes(rnd);
        }
    }
}