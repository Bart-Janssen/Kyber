package Kyber.Algorithm;

public class UnpackedCipherText
{
    private short[][] bp;
    private short[] v;

    public short[][] getBp() {
        return bp;
    }

    protected void setBp(short[][] bp) {
        this.bp = bp;
    }

    public short[] getV() {
        return v;
    }

    protected void setV(short[] v) {
        this.v = v;
    }
}