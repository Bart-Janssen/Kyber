package Kyber;

import Kyber.Algorithm.KeyPair;
import Kyber.smartcard.KeyAppletSmartCard;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.List;

public class KeyServer extends Server
{
    private KeyAppletSmartCard smartCard;

    public KeyServer(int mode, boolean reUpdate, boolean showSmartCardLogging) throws Exception
    {
        super.mode = mode;
        this.connectSmartCard(showSmartCardLogging);

        final String publicKeyFile1 = "public.key";
        if (reUpdate)
        {
            KeyPair keyPair = new KyberService().generateKeys(super.mode);
            //Explicitly not using super.privateKey.
            byte[] privateKey = keyPair.getPrivateKey();
            super.publicKey = keyPair.getPublicKey();

            File outputFile = new File(publicKeyFile1);
            outputFile.delete();
            try (FileOutputStream outputStream = new FileOutputStream(outputFile))
            {
                outputStream.write(super.publicKey);
            }
            System.out.print("[Server]  : Public Key length: " + super.publicKey.length + " | ");super.print(super.publicKey);
            System.out.print("[Server]  : Private Key length: " + privateKey.length + " | ");super.print(privateKey);
            this.smartCard.storePrivateKey(keyPair.getPrivateKey());
        }
        else
        {
            File publicKeyFile = new File(publicKeyFile1);
            try (FileInputStream inputStream = new FileInputStream(publicKeyFile))
            {
                byte[] publicKeyBytes = new byte[(int)publicKeyFile.length()];
                inputStream.read(publicKeyBytes);
                super.publicKey = publicKeyBytes;
            }
        }
    }

    private void connectSmartCard(boolean showSmartCardLogging)
    {
        try
        {
            List<CardTerminal> readers = TerminalFactory.getDefault().terminals().list();
            Card card = readers.get(0).connect("T=1");
            this.smartCard = new KeyAppletSmartCard(super.mode, card, showSmartCardLogging);
            this.smartCard.selectPQCApplet();
        }
        catch (Exception e)
        {
            System.out.println("Not able to receive private key, cannot connect to smart card.");
        }
    }

    @Override
    public byte[] getPublic()
    {
        return super.publicKey;
    }

    @Override
    public void decapsulate(byte[] encapsulation) throws Exception
    {
        super.aesKey = new KyberService().decapsulate(super.mode, this.smartCard.obtainPrivateKey(), encapsulation);
        System.out.print("[Server]  : Decapsulated secret: " + super.aesKey.length + " | ");super.print(super.aesKey);
    }
}