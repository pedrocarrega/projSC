package server;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * 
 * @author Francisco Rodrigues, n50297; Pedro Carrega, n49480; Vasco Ferreira, n49470
 *
 */

public class MsgFileServer {

	/**
	 * @param args - server port
	 * @throws NumberFormatException
	 * @throws IOException
	 */
	
	public static void main(String[] args) throws NumberFormatException, IOException {

		System.out.println("servidor: main");
		MsgFileServer server = new MsgFileServer();
		server.startServer(args[0]);
	}

	/**
	 * Starts the server and opens it to recieve connections
	 * 
	 * @param args - server port
	 * @throws NumberFormatException
	 * @throws IOException
	 */
	
	private void startServer(String args) throws NumberFormatException, IOException {

		//ServerSocket sSoc = null;
		SSLServerSocket sSoc = null;
		try {
//			sSoc = new ServerSocket(Integer.parseInt(args));
			SSoc = new
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault( );
			SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(Integer.parseInt(args));
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		while(true) {
			try {
				SSLServerSocket inSoc = new SSLSimpleServer(ss.accept()).start( );
				//Socket inSoc = sSoc.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("thread do server para cada cliente");
		}

		/**
		 * Processes client
		 */
		
		public void run(){
			try {

				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

				System.out.println("Client Conected");

				File f = new File("users.txt");

				if(!f.exists()) {
					f.createNewFile();
				}

				String user = (String)inStream.readObject();
				String password = (String)inStream.readObject();


				autenticacao(f, user, password, outStream);

				boolean executa = true;
				
				while(executa) {
					try {
						String comando = (String)inStream.readObject();//leitura do comando do cliente
						System.out.println("Comando recebido: " + comando);
						trataComando(comando, inStream, outStream, user);
						
						if(comando.equals("quit")){
							executa = false;
						}
					} catch (SocketException e) {
						executa = false;
						socket.close();
						System.out.println("O utilizador " + user + " disconectou-se por razoes desconhecidas");
					}
				}
				
				socket.close();

			} catch (IOException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}

		/**
		 * Checks if user exists, creates it in case it doesnt exist
		 * 
		 * @param f - file containing users information
		 * @param user - userID
		 * @param password
		 * @param out - to send objects to client
		 * @throws FileNotFoundException
		 * @throws IOException
		 */
		
		private void autenticacao(File f, String user, String password, ObjectOutputStream out) throws FileNotFoundException, IOException {

			//Ja faz conforme o que o pedro fez, ou seja no merge aproveitar isto
			int i = UserManager.validateUser(user, password);

			if(i == 0) {
				System.out.println("Este utilizador nao existe. Assim, vai ser criada uma conta com este username e password");
				out.writeObject(0);//enviar 0 se o cliente nao existe
			}else if(i == 1) {
				System.out.println("Sessao iniciada");
				out.writeObject(1);//enviar 1 se o cliente existe e a password estiver correta
			} else {
				System.out.println("Passe incorreta, este cliente vai fechar");
				out.writeObject(-1);//enviar -1 se a password esta incorreta
				this.socket.close();//para fechar o cliente
				return;
			}

		}
		
		/**
		 * @param comando
		 * @param inStream
		 * @param outStream
		 * @param user - userID
		 * @throws IOException
		 * @throws ClassNotFoundException
		 */
		
		private void trataComando(String comando, ObjectInputStream inStream, ObjectOutputStream outStream, String user) throws IOException, ClassNotFoundException {

			String[] splited = comando.split("\\s+");

			switch(splited[0]) {
			case "store":
				storeFiles(inStream, outStream, splited, user);
				break;
			case "list":
				list(inStream, outStream, splited, user);
				break;
			case "remove":
				remove(inStream, outStream, splited, user);
				break;
			case "users":
				users(inStream, outStream, splited, user);
				break;
			case "trusted":
				trusted(inStream, outStream, splited, user);
				break;
			case "untrusted":
				untrusted(inStream, outStream, splited, user);
				break;
			case "download":
				download(inStream, outStream, splited, user);
				break;
			case "msg":
				msg(inStream, outStream, splited, user);
				break;
			case "collect":
				collect(inStream, outStream, splited, user);
				break;
			case "quit":
				quit(user);
				break;
			}
		}

		/**
		 * @param inStream
		 * @param out
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws ClassNotFoundException
		 * @throws IOException
		 */
		//Já cifra
		private void storeFiles(ObjectInputStream inStream, ObjectOutputStream out, String[] splited, String user) throws ClassNotFoundException, IOException {

			KeyGenerator kg;
			SecretKey key;
			Cipher c = null;			
			
			for(int i = 1; i < splited.length; i++) {

				File f = new File("users/" + user + "/files/" + splited[i]);

				if(!f.exists()) {
					
					try {
						kg = KeyGenerator.getInstance("AES");
						kg.init(128);
						key =	kg.generateKey();
						c = Cipher.getInstance("AES");
						c.init(Cipher.ENCRYPT_MODE, key);
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchPaddingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					out.writeObject(new Boolean(true));//se ficheiro nao existe envia true de sucesso

					boolean fileClientExist = (boolean)inStream.readObject();

					if(fileClientExist) {
						
						int index = splited[i].lastIndexOf(".");
						String fileName = splited[i].substring(0, index);
						
						CipherOutputStream cos;
						FileOutputStream newFile = new FileOutputStream("users/" + user + "/files/" + fileName + ".cif");
						cos = new CipherOutputStream(newFile, c);
						byte[] fileByte = new byte[1024];
						int tamanho;
						int quantos;
							
						while((boolean)inStream.readObject()){//qd recebe false sai do ciclo
							tamanho = (int)inStream.readObject();
							quantos = inStream.read(fileByte, 0, tamanho);
							cos.write(fileByte);	
						}
						cos.close();
						newFile.close();
						
						System.out.println("O ficheiro " + splited[i] + " foi adicionado com sucesso");
					}
				} else {
					//escrever false para o cliente
					out.writeObject(new Boolean(false));
					System.out.println("O ficheiro " + splited[i] + " ja existe!");
				}
			}
		}

		/**
		 * lists the names of the files stored by the user
		 * 
		 * @param inStream
		 * @param outStream
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws IOException
		 */
		
		private void list(ObjectInputStream inStream, ObjectOutputStream outStream, String[] splited, String user) throws IOException {

			File folder = new File("users/" + user + "/files");
			File[] listOfFiles = folder.listFiles();
			List<String> result = new ArrayList<String>();

			for (int i = 0; i < listOfFiles.length; i++) {
				if (listOfFiles[i].isFile()) {
					result.add(listOfFiles[i].getName());
				}
			}
			outStream.writeObject(result);
			System.out.println("Os nomes dos ficheiros foram enviados");
		}

		/**
		 * removes an user file
		 * 
		 * @param inStream
		 * @param out
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws IOException
		 */
		
		private void remove(ObjectInputStream inStream, ObjectOutputStream out, String[] splited, String user) throws IOException{
			File apagar;

			for(int i = 1; i < splited.length; i++){
				apagar = new File("users/" + user + "/files/" + splited[i]);
				out.writeObject(apagar.delete());


			}
		}
		
		/**
		 * presents all created users
		 * 
		 * @param inStream
		 * @param outStream
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws IOException
		 */
		
		private void users(ObjectInputStream inStream, ObjectOutputStream outStream, String[] splited, String user) throws IOException {

			File f = new File("users.txt");

			BufferedReader br = new BufferedReader(new FileReader(f.getName()));
			List<String> result = new ArrayList<String>();

			try {
				String line = br.readLine();

				while (line != null) {
					String[] userName = line.split(":");
					result.add(userName[0]);
					line = br.readLine();
				}

			} finally {
				br.close();
			}
			outStream.writeObject(result);
		}

		/**
		 * adds a trusted userID
		 * 
		 * @param inStream
		 * @param outStream
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws IOException
		 */
		
		private void trusted(ObjectInputStream inStream, ObjectOutputStream outStream, String[] splited,
				String user) throws IOException {

			for(int i = 1; i < splited.length; i++) {
				System.out.println(splited[i]);
				boolean teste = userExistsServer(splited[i]);
				if(teste) {
					if(userExistsTrusted(splited[i], user)) {
						outStream.writeObject(-1);//envia -1 se o user a adicionar ja esta nos trusted
						System.out.println("O utilizador" + splited[i] + "ja existe nos trustedIDs");
					} else {
						File f = new File("users/" + user + "/trustedUsers.txt");
						FileWriter fw = new FileWriter(f,true);
						fw.write(splited[i] + "\n");
						System.out.println("O utilizador " + splited[i] + " foi adicionado com sucesso");
						fw.close();
						outStream.writeObject(1); //envia 1 se e adicionado com sucesso
					}
				} else {
					System.out.println("O utilizador " + splited[i] + " nao existe no servidor");
					outStream.writeObject(0);//envia 0 se o user a adicionar nao existe no servidor
				}
			}
		}

		/**
		 * removes a trusted userID
		 * 
		 * @param inStream
		 * @param outStream
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws IOException
		 */
		
		private void untrusted(ObjectInputStream inStream, ObjectOutputStream outStream, String[] splited,
				String user) throws IOException {

			for(int i = 1; i < splited.length; i++) {
				if(!userExistsTrusted(splited[i], user)) {
					outStream.writeObject(-1);//envia -1 se o user a adicionar ja esta nos trusted
					System.out.println("O utilizador" + splited[i] + "nao existe nos Trusted Users");
				} else {
					String currentLine;
					File f = new File("users/" + user + "/trustedUsers.txt");
					File tempFile = new File("users/trustedUsers.txt");
					tempFile.createNewFile();
					FileWriter fw = new FileWriter(tempFile,true);
					BufferedReader reader = new BufferedReader(new FileReader(f));

					while((currentLine = reader.readLine()) != null) {
						if(!currentLine.equals(splited[i])) {
							fw.write(currentLine + "\n");
						}
					}

					fw.close();
					reader.close();
					f.delete();

					if(tempFile.renameTo(new File("users/" + user + "/trustedUsers.txt"))) {
						outStream.writeObject(1);
					}else {
						outStream.writeObject(0);
					}
				}
			}
		}

		/**
		 * downloads a file from another user that trusts the logged on user
		 * 
		 * @param inStream
		 * @param outStream
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws IOException
		 */
		
		private void download(ObjectInputStream inStream, ObjectOutputStream outStream, String[] splited, String user) throws IOException {
			
			String userID = splited[1];
			
			if(userID.equals(user)){
				System.out.println("Nao pode fazer o download de um ficheiro da sua conta");
			}
			
			if(userExistsServer(userID)){
				if(userExistsTrusted(user, userID)){
					
					String fileName = splited[2];
					File f = new File("users/" + userID + "/files/" + fileName);
					
					if(f.exists()) {
						
						outStream.writeObject(1);
						
						FileInputStream fileStream = new FileInputStream(f);
						byte[] fileByte = new byte[1024];
						int aux;
						
						while((aux = fileStream.read(fileByte)) != -1){
							outStream.writeObject(new Boolean (true)); //envia true enqt o ciclo esta a correr
							outStream.writeObject(aux);
							outStream.write(fileByte, 0, aux);
							outStream.flush();
						}
						
						outStream.writeObject(new Boolean(false));
						
						fileStream.close();
						
					} else {
						//caso o ficheiro que vai ser sacado nao exista
						System.out.println("O ficheiro " + fileName + " nao existe");
						outStream.writeObject(0);
					}
				} else {
					//caso o user exista no servidor mas o client n esteja na lista de amigos
					System.out.println("Users em questao nao sao amigos");
					outStream.writeObject(-1);
				}
				
			} else {
				System.out.println("O user q o cliente procura nao existe");
				outStream.writeObject(-2);
			}
		}

		/**
		 * sends a message to a user that trusts the logged in user
		 * 
		 * @param inStream
		 * @param outStream
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 */
		
		private void msg(ObjectInputStream inStream, ObjectOutputStream outStream, String[] splited, String user) {
			try {
					if(userExistsServer(splited[1]) && !splited[1].equals(user)) {
						File mail = new File("users/" + splited[1] + "/inbox.txt");
						StringBuilder msg = new StringBuilder();

						if(userExistsTrusted(splited[1], user)){
							FileWriter fw = new FileWriter(mail,true); //the true will append the new data
							
							for(int i = 2; i < splited.length; i++) {
								msg.append(splited[i] + " ");
							}
							
							fw.write("Sent from: " + user + "\nMessage: " + msg.toString() + "\n\n");//appends message to the file
							fw.close();
							outStream.writeObject(1);
						}else {
							outStream.writeObject(0);
						}
					}else if(userExistsServer(splited[1]) && splited[1].equals(user)){
						outStream.writeObject(-1);
					}else {
						outStream.writeObject(-2);
					}
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		/**
		 * presents on screen all unread messages of the logged in user
		 * 
		 * @param inStream
		 * @param outStream
		 * @param splited - input string splited by spaces
		 * @param user - userID
		 * @throws IOException
		 */
		
		private void collect(ObjectInputStream inStream, ObjectOutputStream outStream, String[] splited,
				String user) throws IOException {

			File inbox = new File("users/" + user + "/inbox.txt");
			BufferedReader reader = new BufferedReader(new FileReader(inbox));
			String currentLine;
			StringBuilder sb = new StringBuilder();
			int counter = 0;

			while((currentLine = reader.readLine()) != null) {
				sb.append(currentLine + "\n");
				counter++;
			}

			reader.close();

			if(counter > 0) {
				outStream.writeObject(sb.toString());
				inbox.delete();
				File newInbox = new File("users/" + user + "/inbox.txt");
				newInbox.createNewFile();				
			}else {
				outStream.writeObject("Nao tem mensagens por ler");
			}
		}
		
		/**
		 * disconnects from the server
		 * 
		 * @param user - userID
		 */
		
		private void quit(String user) {
			System.out.println("O client " + user + " vai disconectar");
		}
		
		
		/**
		 * checks if the logged in user is trusted
		 * 
		 * @param userAdd - logged in userID
		 * @param userClient - userID
		 * 
		 * @return true in case the logged in user is trusted, false otherwise
		 * 
		 * @throws IOException
		 */
		
		private boolean userExistsTrusted(String userAdd, String userClient) throws IOException {

			try {
				File f = new File("users/" + userClient + "/trustedUsers.txt");
				BufferedReader br = new BufferedReader(new FileReader(f.getCanonicalPath()));
				String line = br.readLine();
				String userName;

				while(line != null) {
					userName = line;
					if(userName.equals(userAdd)) {
						br.close();
						return true;
					}
					line = br.readLine();
				}
				br.close();
				return false;

			} catch (FileNotFoundException e) {
				System.out.println("Erro em userExists, o ficheiro userTrusted nao existe no servidor");
				e.printStackTrace();
			}
			return false;
		}

		
		/**
		 * checks if the userID exists on server
		 * 
		 * @param user - userID
		 * 
		 * @return true in case the user exists on server, false otherwise
		 * 
		 * @throws IOException
		 */
		
		private boolean userExistsServer(String user) throws IOException {

			File f = new File("users.txt");

			try {

				BufferedReader br = new BufferedReader(new FileReader(f.getName()));
				String line = br.readLine();
				String[] userName;

				while(line != null) {
					userName = line.split(":");
					if(userName[0].equals(user)) {
						br.close();
						return true;
					}
					line = br.readLine();
				}
				br.close();
				return false;

			} catch (FileNotFoundException e) {
				System.out.println("Erro em userExists, o ficheiro users nao existe no servidor");
				e.printStackTrace();
			}
			return false;
		}
		
		/**
		 * 
		 * @param username
		 * @param password
		 * @return true se o user for valido false caso contrario
		 */
		private boolean verifyData(String username, String password) {
			File f = new File("users.txt");
			
			try {
				BufferedReader br = new BufferedReader(new FileReader(f.getName()));
				String linha;
				
				while((linha = br.readLine()) != null) {
					String[] linhaSplitted = linha.split(":");
					if(linhaSplitted[0].equals(username)) {
						String pwHashed = UserManager.hashingDados(username + ":" + password);
						br.close();
						return linha.equals(pwHashed);
					}
				}	
				br.close();
			} catch (FileNotFoundException e) {
				System.out.println("Erro em verifyData, o ficheiro users nao existe no servidor");
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return false;
		}
	}
}
