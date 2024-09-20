package Kyber.smartcard;

import javax.smartcardio.Card;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class KyberKeyStoreSmartCard extends SmartCard
{
    private final byte[] kyberKeyStoreAppletAID = new byte[]{(byte)0x50,(byte)0x51,(byte)0x43,(byte)0x20,(byte)0x4B,(byte)0x65,(byte)0x79,(byte)0x73,(byte)0x74,(byte)0x6F,(byte)0x72,(byte)0x65};

    public KyberKeyStoreSmartCard(int mode, Card card, boolean showSmartCardLogging)
    {
        super(mode, card, showSmartCardLogging);
    }

    public void selectKyberKeyStoreApplet() throws Exception
    {
        super.selectApplet(this.kyberKeyStoreAppletAID);
    }

    public void storeKyberPrivateKey(byte[] privateKey) throws Exception
    {
        //Set private key size
        {
            byte[] privateKeySize = new byte[2];
            privateKeySize[0] = (byte)((super.keySize>>8)&0xFF);
            privateKeySize[1] = (byte)((super.keySize)&0xFF);
            CommandAPDU command = new APDU(0x00, 0x00, 0x00, 0x00, privateKeySize, 0x00).create();
            ResponseAPDU response = super.transmit(command);
            if (super.showSmartCardLogging) {System.out.print("Command:  "); super.print(command.getBytes());}
            if (super.showSmartCardLogging) {System.out.print("Response: "); super.print(response.getBytes());}
        }
        int fullChunks = privateKey.length / 255;
        int lastChunk = privateKey.length % 255;

        int offset = 0;
        for (int i = 0; i < fullChunks + ((lastChunk > 1) ? 1 : 0); i++)
        {
            int chunkSize = (i == fullChunks) ? lastChunk : 255;
            byte[] slice = new byte[chunkSize];
            System.arraycopy(privateKey, offset, slice, 0, chunkSize);
            offset+=chunkSize;
            CommandAPDU command = new APDU(0x00,0x00,0x00,0x01,slice, 0x00).create();
            ResponseAPDU response = super.transmit(command);
            if (super.showSmartCardLogging) {System.out.print("Command:  "); super.print(command.getBytes());}
            if (super.showSmartCardLogging) {System.out.print("Response: "); super.print(response.getBytes());}
        }
    }

    public byte[] obtainPrivateKey() throws Exception
    {
        //Check private key size
        {
            byte[] privateKeySize = new byte[2];
            privateKeySize[0] = (byte)((super.keySize>>8)&0xFF);
            privateKeySize[1] = (byte)((super.keySize)&0xFF);
            CommandAPDU command = new APDU(0x00, 0x00, 0x00, 0x03, privateKeySize, 0x00).create();
            ResponseAPDU response = super.transmit(command);
            if (super.showSmartCardLogging) {System.out.print("Command:  "); super.print(command.getBytes());}
            if (super.showSmartCardLogging) {System.out.print("Response: "); super.print(response.getBytes());}
            if (response.getSW() == 0x6389) throw new RuntimeException("Key size does not match in smart card.");
        }
        byte[] privateKey = new byte[super.keySize];
        ResponseAPDU response;
        int offset = 0;
        int chunkSize;
        do
        {
            chunkSize = (offset+255 > super.keySize) ? super.keySize-offset : 255;
            CommandAPDU command = new APDU(0x00,0x00,0x00,0x02,0x00).create();
            response = super.transmit(command);
            if (super.showSmartCardLogging) {System.out.print("Command:  "); super.print(command.getBytes());}
            if (super.showSmartCardLogging) {System.out.print("Response: "); super.print(response.getBytes());}
            System.arraycopy(response.getData(), 0, privateKey, offset, chunkSize);
            offset+=255;
        }
        while (response.getSW() == 0x5000);
        return privateKey;
    }
}