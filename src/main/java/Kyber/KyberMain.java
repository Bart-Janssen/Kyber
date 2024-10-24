package Kyber;

public class KyberMain
{
    public static void main(String[] args)
    {
        try
        {
            for (int i = 0; i < 1; i++)
            {
                System.out.println(i);
//                            Server server = new KeyServer(512, true, true);
                Server server = new JCEServer(512);
//                Server server = new SmartCardServer(512, true);


                Client client = new SmartCardClient(512, true);
//                Client client = new JCEClient(512);
                client.setServerPublic(server.getPublic());

                byte[] encapsulation = client.encapsulate();

                //Send encapsulation over insecure network to server
                System.out.print("[Network] : Encapsulated secret: " + encapsulation.length + " | ");print(encapsulation);

//            new BufferedReader(new InputStreamReader(System.in)).readLine();

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