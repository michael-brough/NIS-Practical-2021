import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Client implements Runnable {

	private static Socket clientSocket = null;
	private static ObjectOutputStream os = null;
	private static ObjectInputStream is = null;
	private static BufferedReader inputLine = null;
	private static BufferedInputStream bis = null;
	private static boolean closed = false;

	private static final String SHA2_ALGORITHM = "SHA-256"; // for caption hashing
	private static final String SHA3_256_ALGORITHM = "SHA3-256"; // for image hashing
	private static final Random RANDOM = new SecureRandom();


	// The default port and host
	static int portNumber = 5000;
	static String host = "localhost";

	/********** new variables ***************/

	// Client RSA key pair
	private static PrivateKey privateKey;
	private static PublicKey publicKey;

//	public static PublicKey otherKey;

	// CA public key
	private static PublicKey CA_publicKey;

	// Session key from server
	private static SecretKey sessionKey;

	static byte[] sessionKeyAsBytes = null;

	// Public key from another client
	static PublicKey otherClientKey;

	static final byte[] RANDOM_SALT = createRandSalt();

	private static final String ENCODE_STRING = "r2hQrcPmLY2XzhUDM9DaPZzjQZdpUnEZWMAjUCEhwXzmclZx3qCQNtkPxipKl9sygfd";
	/*------------------------------------------------------------------------*/
	public static void main(String[] args)
	{

		System.out.println("\n************************************************");
		if (args.length < 2)
			System.out.println("Default Server: " + host + "\nDefault Port: " + portNumber);
		else
		{
			host = args[0];
			portNumber = Integer.valueOf(args[1]).intValue();
			System.out.println("Server: " + host + "\nPort: " + portNumber);
		}
		System.out.println("************************************************\n");

		// generate client key pair
		genKeys();

		// Open a socket on a given host and port. Open input and output streams.
		try
		{
			clientSocket = new Socket(host, portNumber);
			inputLine = new BufferedReader(new InputStreamReader(System.in));
			os = new ObjectOutputStream(clientSocket.getOutputStream());
			is = new ObjectInputStream(clientSocket.getInputStream());
		} catch (UnknownHostException e) {
			System.err.println("Unknown " + host);
		} catch (IOException e) {
			System.err.println("No Server found. Please ensure that the Server program is running and try again.");
		}

		/*
		 * If everything has been initialized then we want to write some data to the
		 * socket we have opened a connection to on the port portNumber.
		 */
		if (clientSocket != null && os != null && is != null) {
			try
			{
				// Create a thread to read from the server.
				new Thread(new Client()).start();
				while (!closed)
				{
					// Read input from Client

					String msg = (String) inputLine.readLine().trim();

					//@Alice:sendfile img,caption

					if ((msg.split(":").length > 1))
					{
						if (msg.split(":")[1].toLowerCase().startsWith("sendfile")) {
							String imageData = msg.split(":")[1];
							String[] splitImage = imageData.split(",");
							//[[sendfile img], [caption]]
							String imgName = splitImage[0].substring(9);
							String caption = splitImage[1];
							System.out.println("image name is " + imgName + " and caption is " + caption);
							File sfile = new File(imgName);

							if (!sfile.exists()) {
								System.out.println("File Doesn't exist!!");
								continue;
							}

							// read in file bytes into byte []
							byte [] mybytearray  = Files.readAllBytes(sfile.toPath());


							//System.out.println("length of all image bytes is " + stuff.length);


							// Divider bytes to add as a buffer for concatenation
							byte[] dividerBytes = ENCODE_STRING.getBytes();

							// Hash the image data
							byte[] hashedOnce = generateImageChecksum(imgName, SHA3_256_ALGORITHM);

							// Hash the image caption
							byte[] hashedCap = createSHA2Hash(caption);

							ByteArrayOutputStream combHashes = new ByteArrayOutputStream();
							combHashes.write(hashedOnce);
							combHashes.write(dividerBytes);
							combHashes.write(hashedCap);

							// Combine the hashes
							byte[] totalHash = combHashes.toByteArray();
							String combHashString = new String(totalHash);
							System.out.println("Combined hash value is " + combHashString);

							// Encrypt with asymmetric private key
							byte[] encryptedOnce = encryptRSAPri(privateKey, totalHash);
							String encrypteOnceString = new String(encryptedOnce);
							System.out.println("Encrypted with asymmetric key is " + combHashString);
//							System.out.println("encryped once bytes " + encryptedOnce.length);

							ByteArrayOutputStream outputStream = new ByteArrayOutputStream();


//							System.out.println("Divider bytes is " + dividerBytes.length);

							outputStream.write(encryptedOnce);
							outputStream.write(dividerBytes);
							outputStream.write(mybytearray);

							byte[] message = outputStream.toByteArray();
							String messageString = new String(message);
							System.out.println("Concatenated message and hash is " + messageString);
//							System.out.println("Concatenated message is of size " + message.length);

							//message = [encryptedOnce + dividerBytes + stuff]

							byte[] compressedEncryptedOnce = compressData(message);
							String compressedOnceString = new String(compressedEncryptedOnce);
							System.out.println("Compressed string is  " + compressedOnceString);
							// Encrypt with symmetric session key

							byte[] encryptedTwice = ecbEncrypt(sessionKey, compressedEncryptedOnce);
							String encryptedTwiceString = new String(encryptedTwice);
							System.out.println("After aes encrpytion  " + encryptedTwiceString);
							// convert session to byte array
							if (sessionKey != null){
								sessionKeyAsBytes = sessionKey.getEncoded();
							}

							// ecnrypt encoded session key with public key
							byte[] encryptedKey = encryptRSAPub(otherClientKey, sessionKeyAsBytes);
							String encryptedKeyString = new String(encryptedKey);
							System.out.println("Session Key encrypted with public key is " + encryptedKeyString);

							ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();

							outputStream2.write(encryptedTwice);
							outputStream2.write(dividerBytes);
							outputStream2.write(encryptedKey);

							byte[] fullyencryptedMessage = outputStream2.toByteArray();
							String fullyEncrypted = new String(fullyencryptedMessage);
							System.out.println("Fully encrypted message is " + fullyEncrypted);
							// fulltencryptedMessage = [encryptedTwice + dividerBytes + encryptedKey]

							os.writeObject(msg);

							//write encrypted message to object
							os.writeObject(fullyencryptedMessage);
							os.flush();

						}
						else
						{
							os.writeObject(msg);
							os.flush();
						}
					}

					// Check the input for broadcast files
					else if (msg.toLowerCase().startsWith("sendfile")) {

						File sfile = new File(msg.split(" ",2)[1]);

						if (!sfile.exists()) {
							System.out.println("File Doesn't exist!!");
							continue;
						}

						byte [] mybytearray  = new byte [(int)sfile.length()];
						FileInputStream fis = new FileInputStream(sfile);
						bis = new BufferedInputStream(fis);
						while (bis.read(mybytearray,0,mybytearray.length)>=0) {
							bis.read(mybytearray,0,mybytearray.length);
						}
						os.writeObject(msg);
						os.writeObject(mybytearray);
						os.flush();
					}

					else {
						os.writeObject(msg);
						os.flush();
					}
				}

				// close open streams and sockets
				os.close();
				is.close();
				clientSocket.close();

			} catch (IOException e) {
				System.err.println("IOException:  " + e);
			} catch (Exception e) {
				System.out.println(e);;
			}
		}
	}

	/*------------------------------------------------------------------------*/
	/*
	 * Generate a random nonce of size 12 to eliminate simple encryption cases
	 */
	public static byte[] getRandomNonce() {
		byte[] nonce = new byte[12];
		new SecureRandom().nextBytes(nonce);
		return nonce;
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Generate private-public key pair
	 */
	private static void genKeys() {
		try {
			System.out.println("************************************************");
			System.out.println("   Generating client public-private keys");

			// generate keys of size 2048 bits
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair pair = gen.generateKeyPair();

			// extract the key-pair
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();

			System.out.println("   Successfully created client public-private keys");
			System.out.println("************************************************\n");
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Acquire CA's public key
	 */
	static void getCAPubKey() {
		try {
			System.out.println("\n************************************************");
			System.out.println("   Receiving CA's public key");

			// receive key
			byte[] key_data = (byte[]) is.readObject();

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key_data);
			CA_publicKey = keyFactory.generatePublic(publicKeySpec);

			System.out.println("   CA's public key successfully received");
			System.out.println("************************************************\n");
		} catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Send Client public key over to CA
	 */
	private static void sendPub() {
		try {
			System.out.println("\n************************************************");
			// send public key to server
			System.out.println("   Sending Public Key to CA");

			// convert key to bytes
			byte [] key_bytes = publicKey.getEncoded();

			// send to server
			os.writeObject(key_bytes);
			os.flush();
			System.out.println("   Public Key successfully sent to CA");
			System.out.println("************************************************\n");

		}
		catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Receive a session key from the server.
	 */
	private void receiveSKey() {
		try {
			System.out.println("\n************************************************");
			System.out.println("   Receiving Session Key from Server");

			// decode the base64 encoded string
			byte[] decodedKey = (byte[]) is.readObject();

			// rebuild key using SecretKeySpec
			sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

			System.out.println("   Session key successfully received");
			System.out.println("************************************************\n");

		} catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Receive a public key from another client
	 */
	private void receivePKey() {
		try {
			System.out.println("\n************************************************");
			System.out.println("   Receiving client's Public Key from Server");

			// receive key
			byte[] key_data = (byte[]) is.readObject();

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key_data);
			otherClientKey = keyFactory.generatePublic(publicKeySpec);
			System.out.println("   Public key successfully received");
			System.out.println("************************************************\n");
		} catch (Exception e) {
			System.out.println(e);
		}
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Encrypt data using RSA generated PublicKey and PKCS1Padding
	 */
	public static byte[] encryptRSAPub(PublicKey key, byte[] data) throws GeneralSecurityException {
		//Instantiate Cipher object with instance of RSA with PKCS1 Padding
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		//Initialise it in encrypt mode with provided key
		cipher.init(Cipher.ENCRYPT_MODE, key);

		//returns byte[] of encrypted data
		return cipher.doFinal(data);
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Encrypt data using RSA generated PrivateKey and PKCS1Padding
	 */
	public static byte[] encryptRSAPri(PrivateKey key, byte[] data) throws GeneralSecurityException {
		//Instantiate Cipher object with instance of RSA with PKCS1 Padding
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		//Initialise it in encrypt mode with provided key
		cipher.init(Cipher.ENCRYPT_MODE, key);

		//returns byte[] of encrypted data
		return cipher.doFinal(data);
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Decryption method using ECB and RSA generated key
	 */
	public static byte[] decryptRSAPri(PrivateKey key, byte[] cipherText) throws GeneralSecurityException {
		//Instantiate Cipher object with instance of RSA with PKCS1 Padding
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		//Initialise it in decrypt mode with provided key
		cipher.init(Cipher.DECRYPT_MODE, key);

		//returns byte[] of decrypted data
		return cipher.doFinal(cipherText);
	}

	/*------------------------------------------------------------------------*/
	/*
	 * Decryption method using ECB and RSA generated key
	 */
	public static byte[] decryptRSAPub(PublicKey key, byte[] cipherText) throws GeneralSecurityException {
		//Instantiate Cipher object with instance of RSA with PKCS1 Padding
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		//Initialise it in decrypt mode with provided key
		cipher.init(Cipher.DECRYPT_MODE, key);

		//returns byte[] of decrypted data
		return cipher.doFinal(cipherText);
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Encrypt data using AES session key, the GCM protocol and an initialisation vector
	 */
	public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(128, Hex.decode("000102030405060708090a0b")));
		byte[] encryptedText = cipher.doFinal(pText);
		return encryptedText;

	}


	public static byte[] ecbEncrypt(SecretKey key, byte[] data)
			throws GeneralSecurityException
	{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public static byte[] ecbDecrypt(SecretKey key, byte[] cipherText)
			throws GeneralSecurityException
	{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(cipherText);
	}

	/*------------------------------------------------------------------------*/
	/*
	 * Decrypt data using AES session key, the GCM protocol and an initialisation vector
	 */
	public static byte[] decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(128, iv));
		byte[] plainText = cipher.doFinal(cText);
		return plainText;

	}


	/**Old aes methods to be removed**/
//	/*------------------------------------------------------------------------*/
//	/*
//	 * Encryption method using CBC and AES session key
//	 */
//	public static byte[][] encryptAES(SecretKey key, byte[] data) throws GeneralSecurityException {
//		//Instantiate Cipher object with instance of AES with PKCS5 Padding
//		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//
//		//Initialise it in encrypt mode with provided key
//		cipher.init(Cipher.ENCRYPT_MODE, key);
//
//		//return byte[][] of encrypted data with a random intialisation vector to counteract obvious similarities
//		return new byte[][] { cipher.getIV(), cipher.doFinal(data)};
//	}
//
//
//	/*------------------------------------------------------------------------*/
//	/*
//	 * Decryption methods using CBC and AES generated key
//	 */
//	public static byte[] decryptAES(SecretKey key, byte[] iv, byte[] cipherText) throws GeneralSecurityException {
//		//Instantiate Cipher object with instance of AES and PKCS5 Padding
//		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//
//		//Initialise it in decrypt mode with provided key and new initialisation vector object
//		cipher.init(Cipher.DECRYPT_MODE, key);
//
//		return cipher.doFinal(cipherText);
//	}


	/*------------------------------------------------------------------------*/
	/*
	 * Compress a given byte array using the zip compression algorithm.
	 * Uses openpgp to create a compressed data generator to open a compressed output stream.
	 */
	public static byte[] compressData(byte[] encryptedMessage) throws Exception {
		byte[] compressedOutput;
		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()){
			PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
			try (OutputStream outputStream = pgpCompressedDataGenerator.open(byteArrayOutputStream)){
				outputStream.write(encryptedMessage);
			}
			compressedOutput = byteArrayOutputStream.toByteArray();
//			System.out.println("Compressed data is: " + compressedOutput);
		}
		return compressedOutput;
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Decompress the given data.
	 * Uses pgp to format a readable obj string from the encoded data.
	 */
	public static byte[] decompressData(byte[] messageToUnzip) throws Exception {
		byte[] decompressedData;
		try (ByteArrayInputStream inputStream = new ByteArrayInputStream(messageToUnzip)){
			PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(inputStream);
			PGPCompressedData pgpCompressedData = (PGPCompressedData) pgpObjectFactory.nextObject();
			InputStream original = pgpCompressedData.getDataStream();
			decompressedData = original.readAllBytes();
		}
		return decompressedData;
	}


	/*------------------------------------------------------------------------*/
	public static String bytesToHex(byte[] bytes){
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes){
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}


	/*
	 * Method to generate hash of an image.
	 * Parameters are filePath of image (String)
	 * and the String of the algorithm (SHA3-256)
	 */
	private static byte[] generateImageChecksum(String filePath, String algorithm){

		MessageDigest md;
		try{
			md = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}

		try (InputStream is = new FileInputStream(filePath);
			 DigestInputStream dis = new DigestInputStream(is, md)) {
			while (dis.read() != -1) ; //empty loop to clear the data
			md = dis.getMessageDigest();
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
		return md.digest();
	}


	/*------------------------------------------------------------------------*/
	/*
	 * Create a Random Salt, required for hashing
	 */
	public static byte[] createRandSalt() {
		byte[] salt = new byte[16];
		RANDOM.nextBytes(salt);
		return salt;
	}

	/*------------------------------------------------------------------------*/
	/*
	 * Create hash value using input value and salt using the SHA2 Algorithm.
	 */
	public static byte[] createSHA2Hash(String text) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
		return hash;
	}

	private List<byte[]> splitBytes(byte[] array, byte[] delimiter) {
		List<byte[]> byteArrays = new LinkedList<byte[]>();

		if (delimiter.length == 0) {
			return byteArrays;
		}
		int begin = 0;

		outer: for (int i = 0; i < array.length - delimiter.length + 1; i++) {
			for (int j = 0; j < delimiter.length; j++) {
				if (array[i + j] != delimiter[j]) {
					continue outer;
				}
			}

			// If delimiter is at the beginning then there will not be any data.
			if (begin != i)
				byteArrays.add(Arrays.copyOfRange(array, begin, i));
			begin = i + delimiter.length;
		}

		// delimiter at the very end with no data following?
		if (begin != array.length)
			byteArrays.add(Arrays.copyOfRange(array, begin, array.length));

		return byteArrays;
	}
	/*------------------------------------------------------------------------*/
	/*
	 * Create a thread to read from the server.
	 */
	public void run() {
		/*
		 * Keep on reading from the socket till we receive "Bye" from the
		 * server. Once we received that then we want to break.
		 */
		String responseLine;
		String filename = "";
		String caption = "";
		byte[] ipfile = null;
		FileOutputStream fos = null;
		BufferedOutputStream bos = null;
		File directory_name;
		String full_path;
		String dir_name = "Received_Files";

		try {
			// Exchange public key with CA
			sendPub();
			getCAPubKey();

			while ((responseLine = (String) is.readObject()) != null)  {

				// Condition for Directory Creation
				if (responseLine.equals("Directory Created")) {
					//Creating Receiving Folder
					directory_name = new File(dir_name);
					System.out.println(directory_name.toString());

					if (!directory_name.exists()) {
						directory_name.mkdir();
						System.out.println("New Receiving file directory for this client created!!");
					}
					else {
						System.out.println("Receiving file directory for this client already exists!!");
					}
				}

				// receive session key
				else if (responseLine.equals("Session")) {
					receiveSKey();
				}

				else if (responseLine.equals("Public")) {
					receivePKey();
				}

				// checking for incoming files
				else if (responseLine.startsWith("Sending_File")) {
					try {
						String line = responseLine.split(":")[1];
						//test.png,a
						filename = line.split(",")[0];
						caption = line.split(",")[1];

						full_path = "Received_Files/" + filename;
						ipfile = (byte[]) is.readObject();

						//encryptedTwice, divider, key
						List<byte[]> initialSplit = splitBytes(ipfile, ENCODE_STRING.getBytes());

						//initialSplit = {encryptedTwice, key}

						// TRACE STATEMENT
						// System.out.println("Size of initialSplit byte [] is "+initialSplit.size());

						// Decrypt (public key encryption) the sessino key with the private key of b.
						byte[] sessionKeyFromClient = decryptRSAPri(privateKey, initialSplit.get(1));
						String sessionKeyString = new String(sessionKeyFromClient);
						System.out.println("Decrypted Session Key is " + sessionKeyString);

						// Decrypt (symmetric decryption) the zipped message by using the session key.
						byte[] zipDecrypted = ecbDecrypt(sessionKey, initialSplit.get(0));
						String zipDecryptedString = new String(zipDecrypted);
						System.out.println("Decrypted message using the aes decryption is " + zipDecryptedString);

						// Decompress the message.
						byte[] decompressedData = decompressData(zipDecrypted);
						String decompressedDataString = new String(decompressedData);
						System.out.println("Decompressed message is " + decompressedDataString);

						//decompressedData = [encryptedHash + dividerBytes + img]
						List<byte[]> messageAndHash = splitBytes(decompressedData, ENCODE_STRING.getBytes());

						// TRACE STATEMENT
						// System.out.println("Size of messageAndHash byte [] is " + messageAndHash.size());

						// Decrypt the encrypted hash with the public key of a.
						byte[] decryptedHash = decryptRSAPub(otherClientKey, messageAndHash.get(0));
						String decryptedHashString = new String(decryptedHash);
						System.out.println("Decrypted hash with public key is " + decryptedHashString);

						List<byte[]> combinedHashes = splitBytes(decryptedHash, ENCODE_STRING.getBytes());
						byte[] imageHash = combinedHashes.get(0);
						byte[] captionHash = combinedHashes.get(1);

						// compute our own hash of the image file
						String imgString = new String(messageAndHash.get(1));
						System.out.println("Hash of image file is " + imgString);

						byte[] secondImageHash = generateImageChecksum(filename, SHA3_256_ALGORITHM);
						String secondImageHashString = new String(secondImageHash);
						System.out.println("Generated Image Hash is " + imgString);

						byte[] secondCaptionHash = createSHA2Hash(caption);
						String secondCaptionString = new String(secondCaptionHash);
						System.out.println("Generated Caption Hash is " + secondCaptionString);

						// Compare the hashes.
						boolean hashCompareImage = Arrays.equals(imageHash, secondImageHash);
						boolean hashCompareCaption = Arrays.equals(captionHash, secondCaptionHash);

						// save image file if hashes are equal
						if(hashCompareImage && hashCompareCaption) {
							System.out.println("Hashes are equal. Image successfully received.");
							fos = new FileOutputStream(full_path);
							bos = new BufferedOutputStream(fos);
							bos.write(messageAndHash.get(1));
							bos.flush();
							System.out.println("Image Received.");
							if (caption != "") {
								System.out.println("Received image caption is: " + caption);
							}
							else {
								System.out.println("No caption was sent with the file.");
							}


						}
						else
						{
							System.out.println("Encrypted file received, but hashes do not match");
						}

					}
					finally {
						if (fos != null) fos.close();
						if (bos != null) bos.close();
					}

				}


				else {
					System.out.println(responseLine);
				}


				/* Condition for quitting application */

				if (responseLine.indexOf("*** Bye") != -1)
					break;
			}

			closed = true;
			System.exit(0);

		} catch (Exception e) {

			System.out.println(e);
		}

	}
	/*------------------------------------------------------------------------*/
}