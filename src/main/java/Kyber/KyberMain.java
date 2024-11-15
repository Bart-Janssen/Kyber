package Kyber;

public class KyberMain
{
    public static boolean random = false;
    
    public static void main(String[] args)
    {
        try
        {
            for (int i = 1; i <= 1; i++)
            {
                int mode = 512;
                System.out.println("Iteration: " + i);
//                Server server = new KeyServer(mode, true, true);
//                Server server = new JCEServer(mode);
                Server server = new SmartCardDummyServer(mode);
//                Server server = new SmartCardServer(mode, true);


                Client client = new SmartCardDummyClient(mode);
//                Client client = new JCEClient(mode);

                client.setServerPublic(server.getPublic());

                byte[] encapsulation = client.encapsulate();


                //Send encapsulation over insecure network to server
                System.out.print("[Network] : Encapsulated secret: " + encapsulation.length + " | ");print(encapsulation);

                server.decapsulate(encapsulation);


                //Secret is now shared

                String plain = "This is a secret message.";
                System.out.println("Original Text : " + plain);

                String encryptedText = client.encryptAES(plain);
                System.out.println("Encrypted Text: " + encryptedText);

                String plainText = server.decryptAES(encryptedText);
                System.out.println("Decrypted Text: " + plainText);
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    protected static void print(byte[] data)
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