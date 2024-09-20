package Kyber.smartcard;

import javax.smartcardio.CommandAPDU;

public class APDU
{
    private byte cla;
    private byte ins;
    private byte p1;
    private byte p2;
    private byte[] lc;
    private byte[] le;
    private boolean leAbsent;
    private boolean lcAbsent;
    private byte[] data;

    public APDU(int cla, int ins, int p1, int p2, byte[] data)
    {
        this.cla = (byte)cla;
        this.ins = (byte)ins;
        this.p1 = (byte)p1;
        this.p2 = (byte)p2;
        this.lc = new byte[]{(byte)0x82,0x00,(byte)data.length};
        lcAbsent = false;
        this.data = data;
        this.leAbsent = true;
    }

    public APDU(int cla, int ins, int p1, int p2, int le)
    {
        this.cla = (byte)cla;
        this.ins = (byte)ins;
        this.p1 = (byte)p1;
        this.p2 = (byte)p2;
        this.le = new byte[]{0x00,(byte)le};
        this.data = new byte[0];
        this.leAbsent = false;
        this.lcAbsent = true;
    }

    public APDU(int cla, int ins, int p1, int p2, byte[] data, int le)
    {
        this.cla = (byte)cla;
        this.ins = (byte)ins;
        this.p1 = (byte)p1;
        this.p2 = (byte)p2;
        this.lc = new byte[]{(byte)0x00,(byte)(data.length >> 8),(byte)data.length};
        this.data = data;
        this.le = new byte[]{0x00,(byte)le};
        this.leAbsent = false;
    }

    public CommandAPDU create()
    {
        byte[] apdu = new byte[]
                {
                        this.cla, this.ins, this.p1, this.p2,
                };
        if (!this.lcAbsent) apdu = this.appendByteToArray(apdu, this.lc[2]);
        apdu = this.appendByteArrays(apdu, this.data);
        if (!this.leAbsent) apdu = this.appendByteToArray(apdu, this.le[1]);
        return new CommandAPDU(apdu);
    }

    protected void print(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : data)
        {
            sb.append(String.format("%02X ", b));
        }
        System.out.print(sb);
        System.out.println();
    }

    private byte[] appendByteArrays(byte[] array1, byte[] array2)
    {
        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

    private byte[] appendByteToArray(byte[] array1, byte b)
    {
        byte[] array2 = new byte[] {b};
        byte[] result = new byte[array1.length + 1];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

    public void setCLA(byte cla)
    {
        this.cla = cla;
    }

    public byte getCLA()
    {
        return this.cla;
    }

    public byte getINS()
    {
        return this.ins;
    }

    public byte getP1()
    {
        return this.p1;
    }

    public byte getP2()
    {
        return this.p2;
    }

    public byte[] getData()
    {
        return this.data;
    }

    public void addMac(byte[] mac)
    {
        byte[] data = new byte[this.data.length + mac.length];
        System.arraycopy(this.data, 0, data, 0, this.data.length);
        System.arraycopy(mac, 0, data, this.data.length, mac.length);
        this.data = data;
    }
}