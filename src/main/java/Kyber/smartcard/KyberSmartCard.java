package Kyber.smartcard;

import Kyber.Implementation.SmartCard.Applet;
import Kyber.Models.KyberEncrypted;

import javax.smartcardio.Card;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class KyberSmartCard extends SmartCard
{
    private final byte[] kyberApplet512AID = new byte[]{(byte)0x4B,(byte)0x79,(byte)0x62,(byte)0x65,(byte)0x72};

    public KyberSmartCard(int mode, Card card, boolean showSmartCardLogging)
    {
        super(mode, card, showSmartCardLogging);
    }

    public void selectKyberApplet() throws Exception
    {
        System.out.println("Selecting Kyber...");
        super.selectApplet(this.kyberApplet512AID);
    }

    public void generateKyber512Key() throws Exception
    {
        System.out.println("Generating kyber 512 key pair...");
        CommandAPDU command = new APDU(0x00,0x01,0x00,0x00, 0x00).create();
        ResponseAPDU response = this.transmit(command);
        if (this.showSmartCardLogging) {System.out.print("Command:  "); this.print(command.getBytes());}
        if (this.showSmartCardLogging) {System.out.print("Response: "); this.print(response.getBytes());}
    }

    public byte[] getPublicKey() throws Exception
    {
        System.out.println("Obtaining public key...");
        int index = 0;
        byte[] publicKey = new byte[super.publicKeySize];
        ResponseAPDU response;
        do
        {
            CommandAPDU command = new APDU(0x00,0x05,0x00,0x00, 0x00).create();
            if (this.showSmartCardLogging) {System.out.print("Command:  "); this.print(command.getBytes());}
            response = this.transmit(command);
            if (this.showSmartCardLogging) {System.out.print("Response: "); this.print(response.getBytes());}
            System.arraycopy(response.getData(), 0, publicKey, index, response.getData().length);
            index+=255;
        }
        while (response.getSW() == 0x5000);
        return publicKey;
    }

    public byte[] getPrivateKey()
    {
        //replace this with actual smart card apdu
        return Applet.getInstance().getPrivateKey();
    }

    public KyberEncrypted encapsulate(int mode, byte[] publicKey) throws Exception
    {

        if (mode == 512) return Applet.getInstance().encapsulate((byte)2, publicKey);
//        if (mode == 768) return new KyberAlgorithm().encrypt768(random, publicKey);
//        if (mode == 1024) return new KyberAlgorithm().encrypt1024(random, publicKey);
        throw new RuntimeException("Mode not supported.");
    }

    public byte[] decapsulate(int mode, byte[] encapsulation) throws Exception
    {
        System.out.println("Uploading encapsulation...");
        int full = encapsulation.length/255;
        int rest = encapsulation.length%255;
        for (int i = 0; i < full; i++)
        {
            byte[] encapsulationChunk = new byte[255];
            System.arraycopy(encapsulation,i*255,encapsulationChunk,0,255);
            CommandAPDU command = new APDU(0x00,0x08,0x00,0x00, encapsulationChunk, 0x00).create();
            if (this.showSmartCardLogging) {System.out.print("Command:  "); this.print(command.getBytes());}
            ResponseAPDU response = this.transmit(command);
            if (this.showSmartCardLogging) {System.out.print("Response: "); this.print(response.getBytes());}
        }
        if (rest > 0)
        {
            byte[] encapsulationChunk = new byte[rest];
            System.arraycopy(encapsulation,full*255,encapsulationChunk,0,rest);
            CommandAPDU command = new APDU(0x00,0x08,0x00,0x00, encapsulationChunk, 0x00).create();
            if (this.showSmartCardLogging) {System.out.print("Command:  "); this.print(command.getBytes());}
            ResponseAPDU response = this.transmit(command);
            if (this.showSmartCardLogging) {System.out.print("Response: "); this.print(response.getBytes());}
        }

        System.out.println("Decapsulating...");
        CommandAPDU command = new APDU(0x00,0x03,0x00,0x00, 0x00).create();
        if (this.showSmartCardLogging) {System.out.print("Command:  "); this.print(command.getBytes());}
        ResponseAPDU response = this.transmit(command);
        if (this.showSmartCardLogging) {System.out.print("Response: "); this.print(response.getBytes());}

        return this.getSecret();
    }

    private byte[] getSecret() throws Exception
    {
        System.out.println("Obtaining secret...");
        CommandAPDU command = new APDU(0x00,0x06,0x00,0x00, 0x00).create();
        if (this.showSmartCardLogging) {System.out.print("Command:  "); this.print(command.getBytes());}
        ResponseAPDU response = this.transmit(command);
        if (this.showSmartCardLogging) {System.out.print("Response: "); this.print(response.getBytes());}
        return response.getData();
    }
}