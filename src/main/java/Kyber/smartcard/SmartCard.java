package Kyber.smartcard;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public abstract class SmartCard
{
    private final Card card;
    protected int privateKeySize;
    protected int publicKeySize;
    protected final boolean showSmartCardLogging;

    public SmartCard(int mode, Card card, boolean showSmartCardLogging)
    {
        if (mode == 512)
        {
            this.privateKeySize = 1632;
            this.publicKeySize = 800;
        }
        else if (mode == 768)
        {
            this.privateKeySize = 2400;
            this.publicKeySize = 1184;
        }
        else if (mode == 1024)
        {
            this.privateKeySize = 3168;
            this.publicKeySize = 1568;
        }
        else throw new RuntimeException("Mode not supported.");
        this.card = card;
        this.showSmartCardLogging = showSmartCardLogging;
    }

    protected void selectApplet(byte[] aid) throws Exception
    {
        CommandAPDU command = new APDU(0x00,0xA4,0x04,0x00, aid, 0x00).create();
        ResponseAPDU response = this.transmit(command);
        if (this.showSmartCardLogging) {System.out.print("Command:  "); this.print(command.getBytes());}
        if (this.showSmartCardLogging) {System.out.print("Response: "); this.print(response.getBytes());}
    }

    protected ResponseAPDU transmit(CommandAPDU apdu) throws Exception
    {
        CardChannel channel = this.card.getBasicChannel();
        ResponseAPDU response = channel.transmit(apdu);
        byte[] responseData = response.getBytes();
        return new ResponseAPDU(responseData);
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
}