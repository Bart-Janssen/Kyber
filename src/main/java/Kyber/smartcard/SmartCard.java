package Kyber.smartcard;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public abstract class SmartCard
{
    private final Card card;
    int keySize;
    protected final boolean showSmartCardLogging;

    public SmartCard(int mode, Card card, boolean showSmartCardLogging)
    {
        if (mode == 512) this.keySize = 1632;
        else if (mode == 768) this.keySize = 2400;
        else if (mode == 1024) this.keySize = 3168;
        else throw new RuntimeException("Mode not supported.");
        this.card = card;
        this.showSmartCardLogging = showSmartCardLogging;
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