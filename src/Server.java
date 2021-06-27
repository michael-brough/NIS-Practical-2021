import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/*
 * A chat server that delivers public and private messages and files.
 */
public class Server {

	// The server socket.
	private static ServerSocket serverSocket = null;

	// The client socket.
	private static Socket clientSocket = null;

	// list of clients
	public static ArrayList<clientThread> clients = new ArrayList<clientThread>();

	// server public IP address
	private static InetAddress serverAddress = null;

	// default port number and public IP
	static int portNumber = 5000;
	static String publicIP;

	// number of connected clients
	static int clientNum;

	// Certification Authority keys
	static PrivateKey caPrivateKey;
	static PublicKey caPublicKey;

	// Clients public keys
	static PublicKey aliceKey, bobKey;

	/*------------------------------------------------------------------------*/
	public static void main(String args[]) {

//		Security.addProvider(new BouncyCastleProvider());
		System.out.println("\n************************************************");
		if (args.length < 1)
			System.out.println("Server is running using default port number=" + portNumber);
		else
		{
			portNumber = Integer.valueOf(args[0]).intValue();
			System.out.println("Server is running using specified port number=" + portNumber);
		}

		// Open a server socket on the portNumber (default 1234).
		try
		{
			// print public IP
			getPublicIP();

			// open socket
			serverSocket = new ServerSocket(portNumber);

			// generate CA key pairs
			genCAKeys();

		}
		catch (IOException e)
		{
			System.out.println("Server Socket cannot be created");
		}

		// Create a client socket for each connection and pass it to a new client thread.
		clientNum = 0;
		while (true)
		{
			try {
				clientSocket = serverSocket.accept();
				clientThread curr_client =  new clientThread(clientSocket, clients);
				clients.add(curr_client);
				curr_client.start();
				System.out.println("\nClient "  + ((int)clientNum+1) + " is connected!");
				clientNum++;
			} catch (IOException e)
			{
				System.out.println("Client could not be connected");
			}
		}
	}
	/*------------------------------------------------------------------------*/
	/*
	 * Print out public IP
	 */
	static void getPublicIP() {
		try {
			// find the public ip of server host - enables global client connections
			URL find_ip = new URL("http://checkip.amazonaws.com");
			BufferedReader in = new BufferedReader(new InputStreamReader(find_ip.openStream()));
			// get IP as string
			publicIP = in.readLine();
			System.out.println("Server Public IP is: "+publicIP);
			System.out.println("************************************************");
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}

	/*------------------------------------------------------------------------*/
	/*
	 *	Generate CA public-private key pair
	 */
	static void genCAKeys() {
		try {
			System.out.println("\n************************************************");
			System.out.println("   Generating CA public-private keys");

			// generate keys of size 2048 bits
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair pair = gen.generateKeyPair();

			// extract the key-pair
			caPrivateKey = pair.getPrivate();
			caPublicKey = pair.getPublic();

			System.out.println("   CA public-private keys successfully generated");
			System.out.println("************************************************");
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	}
	/*------------------------------------------------------------------------*/
	/*
	 * Generate self-signed X509 Certificate from client private key and receiver's public key
	 */
	public static X509Certificate makeV1Certificate(PrivateKey caSignerKey, PublicKey caPublicKey)
			throws GeneralSecurityException, IOException, OperatorCreationException
	{
		X509v1CertificateBuilder v1CertBldr = new JcaX509v1CertificateBuilder(
				new X500Name("CN=Issuer CA"),
				BigInteger.valueOf(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() - 1000L * 5),
				new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS),
				new X500Name("CN=Issuer CA"),
				caPublicKey);

		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS");

		return new JcaX509CertificateConverter().setProvider("BCFIPS").getCertificate(v1CertBldr.build(signerBuilder.build(caSignerKey)));
	}
	/*------------------------------------------------------------------------*/
}


/*
 * This client thread class handles individual clients in their respective threads
 * by opening a separate input and output streams.
 */
class clientThread extends Thread {

	private String clientName = null;
	private ObjectInputStream is = null;
	private ObjectOutputStream os = null;
	private Socket clientSocket = null;
	private final ArrayList<clientThread> clients;


	public clientThread(Socket clientSocket, ArrayList<clientThread> clients) {
		this.clientSocket = clientSocket;
		this.clients = clients;
	}

	public void run() {
		ArrayList<clientThread> clients = this.clients;
		try {
			// Create input and output streams for this client.
			is = new ObjectInputStream(clientSocket.getInputStream());
			os = new ObjectOutputStream(clientSocket.getOutputStream());
			String name;

			// acquire and store client Public Key before any communication
			getClientPubKey();

			// Send public key to clients
			sendPub();
			while (true) {
				synchronized(this) {
					this.os.writeObject("\n************************************************");
					this.os.writeObject("Enter Client name :");
					this.os.flush();
					name = ((String) this.is.readObject()).trim();

					if ((name.indexOf('@') == -1) || (name.indexOf('!') == -1)) {
						break;
					} else {
						this.os.writeObject("Username should not contain '@' or '!' characters.");
						this.os.flush();
					}
				}
			}

			// Welcome the new the client.
			System.out.println("Client Name is " + name);

			this.os.writeObject("\n************************************************");
			this.os.writeObject("** Welcome to the image cryptosystem " + name);
			this.os.writeObject("** Use the following commands:\n");
			this.os.writeObject("  /quit to leave this session");
			this.os.writeObject("  /available to see available clients");
			this.os.writeObject("  /initiate @clientName to start a session with another client");
			this.os.writeObject("  /@clientName:sendfile filename,caption to send to the connected client");
			this.os.writeObject("************************************************\n");

			this.os.flush();

//				this.os.writeObject("Directory Created\n");
//				this.os.flush();

			synchronized(this) {
				for (clientThread curr_client : clients) {
					if (curr_client != null && curr_client == this) {
						clientName = "@" + name;
						break;
					}
				}

				// tells the other connected client that another user has connected to the server
				for (clientThread curr_client : clients) {
					if (curr_client != null && curr_client != this) {
						curr_client.os.writeObject(name + " has joined\n");
						curr_client.os.flush();
					}
				}
			}

			// Start conversation
			while (true) {
				this.os.writeObject("Enter command:");
				this.os.flush();

				String line = (String) is.readObject();
				System.out.println("User entered command: "+ line + "\n");

				if (line.startsWith("/quit"))
					break;

				// display online clients
				if(line.startsWith("/available"))
					seeAvailable();

				// initiate a session. Requires 2 clients to be connected
				// example string /initiate @Bob
				if (line.startsWith("/initiate")) {
					String onlineClient = checkOnline(line);
					if(!onlineClient.equals("")) {
						try {
							// generate session key
							SecretKey sessionKey = genAESKey(onlineClient);

							// send session key to the 2 clients
							distributeSession(onlineClient, sessionKey);

							// exchange client public keys - LATER TO USE CERTIFICATE
							// generate certificate using private key of client and reciever's public key
							// PrivateKey caSignerKey, PublicKey caPublicKey
							// X509Certificate cert = makeV1Certificate( , getClientPublicKey());
							exchangePubKeys();


						}
						catch (Exception e) {
							System.out.println(e);
						}
					}
					else{
						os.writeObject("Error with client's name. Check spelling.");
					}
					os.flush();
				}

				// If the message is private send it to the given client.
				if (line.startsWith("@"))
					unicast(line,name);

					// If the message is blocked from a given client.
				else if(line.startsWith("!"))
					blockcast(line,name);

			}

			// Terminate the Session for a particular user
			this.os.writeObject("*** Bye " + name + " ***");
			this.os.flush();
			System.out.println(name + " disconnected.");
			clients.remove(this);

			synchronized(this) {
				if (!clients.isEmpty()) {
					for (clientThread curr_client : clients) {
						if (curr_client != null && curr_client != this && curr_client.clientName != null) {
							curr_client.os.writeObject("*** The user " + name + " disconnected ***");
							curr_client.os.flush();
						}
					}
				}
			}

			this.is.close();
			this.os.close();
			clientSocket.close();

		} catch (IOException e) {

			System.out.println("User Session terminated");

		} catch (ClassNotFoundException e) {

			System.out.println("Class Not Found");
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Display a list of clients who are online
	 */
	public void seeAvailable() {
		try {
			for(clientThread c: clients) {
				os.writeObject(c.clientName);
			}
			os.writeObject("\n");
			os.flush();
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Check if referenced client can be reached
	 */
	public String checkOnline(String line) {
		// extract referenced client's name
		String [] words = line.split(" ");
		String name = words[1];
		try {
			for(clientThread c: clients) {
				if (name.equalsIgnoreCase(c.clientName))
					return name;
			}
		}
		catch (Exception e) {
			System.out.println(e);
		}
		return "";
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Acquire client's public key
	 */
	void getClientPubKey() {
		try {
			System.out.println("\n************************************************");
			System.out.println("   CA receiving key from client");

			//System.out.println("Client num is :"+ Server.clientNum);
			// receive key
			byte[] key_data = (byte[]) is.readObject();

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key_data);
			if(Server.clientNum == 1)
				Server.aliceKey = keyFactory.generatePublic(publicKeySpec);
			else if(Server.clientNum == 2)
				Server.bobKey = keyFactory.generatePublic(publicKeySpec);
			System.out.println("   CA successfully received key from Client");
			System.out.println("************************************************\n");

		}
		catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Send CA's public key to Client
	 */
	public void sendPub() {
		try {
			System.out.println("\n************************************************");
			// send public key to client
			System.out.println("   Sending CA public key to client");

			// convert key to bytes
			byte [] key_bytes = Server.caPublicKey.getEncoded();

			// send to client
			os.writeObject(key_bytes);
			os.flush();
			System.out.println("   Key successfully sent to client");
			System.out.println("************************************************\n");
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Generate session key for 2 clients
	 */
	public SecretKey genAESKey(String otherClient) throws GeneralSecurityException {

		System.out.println("\n************************************************");

		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		System.out.println("CA generated session key for " + this.clientName + " and " + otherClient );

		return keyGenerator.generateKey();
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Distribute session key to 2 clients
	 * THIS NEEDS TO BE ENCRYPTED AT SOME STAGE
	 */
	public void distributeSession(String otherClient, SecretKey sessionKey) {
		System.out.println("\n");
		try {
			// encode session key
			byte [] key_bytes = sessionKey.getEncoded();

			// send session key to other client
			for(clientThread client: clients) {
				if(client.clientName.equals(otherClient)) {
					client.os.writeObject("Session");
					System.out.println("Server sending session key to " + client.clientName);

					client.os.writeObject(key_bytes);
					client.os.flush();
				}
			}

			// send session key to this client
			System.out.println("Server sending session key to "+ this.clientName + "\n");

			this.os.writeObject("Session");
			this.os.writeObject(key_bytes);
			this.os.flush();

			System.out.println("Server successfully distributed a Session key ");
			System.out.println("************************************************\n");
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Sends client's public key to the other client
	 * Public key is encrypted using server private key
	 */
	void exchangePubKeys() {
		System.out.println("\n");
		try
		{
			// encode clients' public keys
			byte [] alice_key_bytes = Server.aliceKey.getEncoded();
			byte [] bob_key_bytes = Server.bobKey.getEncoded();

			// send public key to other client
			clients.get(0).os.writeObject("Public");
			clients.get(0).os.writeObject(bob_key_bytes);
			clients.get(0).os.flush();

			clients.get(1).os.writeObject("Public");
			clients.get(1).os.writeObject(alice_key_bytes);
			clients.get(1).os.flush();

		}
		catch (Exception e)
		{
			System.out.println(e);
		}


	}


	/**** This function transfers message or files to all the client except a particular client connected to the server ***/

	void blockcast(String line, String name) throws IOException, ClassNotFoundException {

		String[] words = line.split(":", 2);

		/* Transferring a File to all the clients except a particular client */

		if (words[1].split(" ")[0].toLowerCase().equals("sendfile"))
		{
			byte[] file_data = (byte[]) is.readObject();

			synchronized(this) {
				for (clientThread curr_client : clients) {
					if (curr_client != null && curr_client != this && curr_client.clientName != null
							&& !curr_client.clientName.equals("@"+words[0].substring(1)))
					{
						curr_client.os.writeObject("Sending_File:"+words[1].split(" ",2)[1].substring(words[1].split("\\s",2)[1].lastIndexOf(File.separator)+1));
						curr_client.os.writeObject(file_data);
						curr_client.os.flush();


					}
				}

				/* Echo this message to let the user know the blocked file was sent.*/

				this.os.writeObject(">>Blockcast File sent to everyone except "+words[0].substring(1));
				this.os.flush();
				System.out.println("File sent by "+ this.clientName.substring(1) + " to everyone except " + words[0].substring(1));
			}
		}

		/* Transferring a message to all the clients except a particular client */

		else
		{
			if (words.length > 1 && words[1] != null) {
				words[1] = words[1].trim();
				if (!words[1].isEmpty()) {
					synchronized (this){
						for (clientThread curr_client : clients) {
							if (curr_client != null && curr_client != this && curr_client.clientName != null
									&& !curr_client.clientName.equals("@"+words[0].substring(1))) {
								curr_client.os.writeObject("<" + name + "> " + words[1]);
								curr_client.os.flush();


							}
						}
						/* Echo this message to let the user know the blocked message was sent.*/

						this.os.writeObject(">>Blockcast message sent to everyone except "+words[0].substring(1));
						this.os.flush();
						System.out.println("Message sent by "+ this.clientName.substring(1) + " to everyone except " + words[0].substring(1));
					}
				}
			}
		}
	}

	/**** This function transfers message or files to all the client connected to the server ***/

	void broadcast(String line, String name) throws IOException, ClassNotFoundException {

		/* Transferring a File to all the clients */


		//encrypt msg.caption
		//encrypt msg.img
		//currentclient.os.writeObject(enc_msg)

		if (line.split("\\s")[0].toLowerCase().equals("sendfile"))
		{

			byte[] file_data = (byte[]) is.readObject();
			synchronized(this){
				for (clientThread curr_client : clients) {
					if (curr_client != null && curr_client.clientName != null && curr_client.clientName!=this.clientName)
					{
						curr_client.os.writeObject("Sending_File:"+line.split("\\s",2)[1].substring(line.split("\\s",2)[1].lastIndexOf(File.separator)+1));
						curr_client.os.writeObject(file_data);
						curr_client.os.flush();

					}
				}

				this.os.writeObject("Broadcast file sent successfully");
				this.os.flush();
				System.out.println("Broadcast file sent by " + this.clientName.substring(1));
			}
		}

		else
		{
			/* Transferring a message to all the clients */

			synchronized(this){

				for (clientThread curr_client : clients) {

					if (curr_client != null && curr_client.clientName != null && curr_client.clientName!=this.clientName)
					{

						curr_client.os.writeObject("<" + name + "> " + line);
						curr_client.os.flush();

					}
				}

				this.os.writeObject("Broadcast message sent successfully.");
				this.os.flush();
				System.out.println("Broadcast message sent by " + this.clientName.substring(1));
			}

		}

	}



	void unicast(String line, String name) throws IOException, ClassNotFoundException {
		//@Alice:sendfile example.jpg
		String[] words = line.split(":", 2);
		//[[Alice], [sendfile example.jpg]]

		if (words[1].split(" ")[0].equals("sendfile")) {
			byte[] file_data = (byte[]) is.readObject();

			for (clientThread curr_client : clients) {
				if (curr_client != null && curr_client != this && curr_client.clientName != null && curr_client.clientName.equals(words[0])) {
					System.out.println("Current client is " + this.clientName);
					curr_client.os.writeObject("Sending_File:" + words[1].split(" ",2)[1].substring(words[1].split("\\s",2)[1].lastIndexOf(File.separator)+1));
					System.out.println(file_data);
					//encrypt file data
					//byte[] encrypted = encryptRSA(this.getClientPubKey(),file_data);
					curr_client.os.writeObject(file_data);
					curr_client.os.flush();
					System.out.println(this.clientName.substring(1) + " transferred a private file to client "+ curr_client.clientName.substring(1));

					//this->Bob
					//curr_client->Alice

					this.os.writeObject("Private File sent to " + curr_client.clientName.substring(1));
					this.os.flush();
					break;

				}
			}
		}

		/* Transferring message to a particular client */

		else
		{

			if (words.length > 1 && words[1] != null) {

				words[1] = words[1].trim();


				if (!words[1].isEmpty()) {

					for (clientThread curr_client : clients) {
						if (curr_client != null && curr_client != this && curr_client.clientName != null
								&& curr_client.clientName.equals(words[0])) {
							curr_client.os.writeObject("<" + name + "> " + words[1]);
							curr_client.os.flush();

							System.out.println(this.clientName.substring(1) + " transferred a private message to client "+ curr_client.clientName.substring(1));

							/* Echo this message to let the sender know the private message was sent.*/

							this.os.writeObject("Private Message sent to " + curr_client.clientName.substring(1));
							this.os.flush();
							break;
						}
					}
				}
			}
		}
	}




}




