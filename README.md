# NIS_Prac
NIS Practical --README--

To compile and run the program:

1. From within the src/ directory
	enter: 
		javac -cp ".;bcpg-jdk15on-169.jar;bcprov-jdk15on-169.jar;bcutil-jdk15on-169.jar;bcpkix-jdk15on-169.jar" *.java
	in the command line. This compiles all the relevant .java files and links the relevant .jar files.
	
2. Once this is completed, you can run the server using:
		java -cp ".;bcpg-jdk15on-169.jar;bcprov-jdk15on-169.jar;bcutil-jdk15on-169.jar;bcpkix-jdk15on-169.jar" Server 
	
	The server will provide a response, printing the port number it is running on.
	It will also print its public IP, which it obtains with a method.
	
3. Once a server is running in a terminal window, in other terminal windows you can run, but still from the src/ directory:
		java -cp ".;bcpg-jdk15on-169.jar;bcprov-jdk15on-169.jar;bcutil-jdk15on-169.jar;bcpkix-jdk15on-169.jar" Client
		
	In the client screen you will be prompted to enter a name for the client. The server terminal will act as a window into 
	the processes that are being carried out.
	Once two clients have been created and connected to the server through their own terminal windows, proceed to step 4.
	
4. Either client can interact with the other over the server. In order to create an interaction session, follow the prompt
   shown in the window by typing /initiate @OtherClient, where OtherClient is the name of the client you wish to initiate a
   session with. If unsure use /available to see all the clients connected to the server.
   
   To send a file to a connected client that you have established a session with use:
   @OtherClient:sendfile imageName,imageCaption
   
   OtherClient is the client you wish to send the image to.
   sendfile is a command.
   imageName is the image you wish to send.
   imageCaption is the caption that you want to send with the image.
   
   Once this is carried out successfully, any client can send an image to any other connected client on the server,
   and the received image will appear in the Received_Files directory.
	


