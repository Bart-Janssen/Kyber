package Kyber.Algorithm;

public class KyberUniformRandom
{
    private short[] uniformR;
    private int uniformI = 0;

    public short[] getUniformR() {
        return uniformR;
    }

    public void setUniformR(short[] uniformR) {
        this.uniformR = uniformR;
    }

    public int getUniformI() {
        return uniformI;
    }

    public void setUniformI(int uniformI) {
        this.uniformI = uniformI;
    }
}