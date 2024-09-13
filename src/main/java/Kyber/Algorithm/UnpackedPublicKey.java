package Kyber.Algorithm;

public class UnpackedPublicKey
{
    private short[][] publicKeyPolyvec;
    private byte[] seed;

    public short[][] getPublicKeyPolyvec() {
        return publicKeyPolyvec;
    }

    protected void setPublicKeyPolyvec(short[][] publicKeyPolyvec) {
        this.publicKeyPolyvec = publicKeyPolyvec;
    }

    public byte[] getSeed() {
        return seed;
    }

    protected void setSeed(byte[] seed) {
        this.seed = seed;
    }
}