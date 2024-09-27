package Kyber.Implementation.SmartCard.dummy;

//Dummy exception for Keccak
public class CryptoException extends RuntimeException
{
    public static int NO_SUCH_ALGORITHM = 1;

    public CryptoException(int noSuchAlgorithm)
    {

    }
}