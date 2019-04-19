package server;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

@SuppressWarnings("deprecation")
public class UserManager {

	private KeyStore ks;

	public static void main(String[] args){

		try(Scanner sc = new Scanner(System.in)){


			String managerPW = sc.nextLine();

			if(encryptionAlgorithms.validMAC(managerPW)) {

				while(true) {

					//apresentar opcoes
					System.out.println(presentOptions());
					//input
					String[] input = sc.nextLine().split(" ");
					int result;

					switch (input[0]) {

					case "add":
						if(addUser(input[1] , input[2], managerPW)) {
							System.out.println("User adicionado com sucesso");
						}else {
							System.out.println("Username ja esta em uso");
						}
						break;

					case "edit":
						result = editUser(input[1], input[2], input[3], managerPW);

						if(result == 0) {
							System.out.println("Este utilizador nao existe\n");
						}else if(result == 1) {
							System.out.println("Password atualizada com sucesso\n");
						} else {
							System.out.println("Passe incorreta\n");
						}

						break;

					case "remove":

						result = removeUser(input[1], input[2], managerPW);

						if(result == 0) {
							System.out.println("Este utilizador nao existe\n");
						}else if(result == 1) {
							System.out.println("Utilizador removido com sucesso\n");
						} else {
							System.out.println("Passe incorreta\n");
						}

						break;

					case "quit":
						System.exit(0); //fecha o programa

					default:
						System.out.println("Comando invalido, por favor volte a inserir o comando\n\n\n");

						break;
					}
				}
			}else {
				throw new InvalidKeyException();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	private static boolean addUser(String username, String password, String managerPW) throws NoSuchAlgorithmException, IOException {


		BufferedWriter bw = new BufferedWriter(new FileWriter(new File("users.txt")));
		BufferedReader br = new BufferedReader(new FileReader(new File("users.txt")));


		String linha;

		while((linha = br.readLine()) != null) {
			String[] lineSplitted = linha.split(":");
			if(lineSplitted[0].equals(username)) {
				bw.close();
				br.close();
				return false;
			}
		}
		bw.write(username + ":" + encryptionAlgorithms.hashingDados(password) + "\n");



		encryptionAlgorithms.atualizaMAC(encryptionAlgorithms.geraMAC(managerPW));
		br.close();
		bw.close();
		return true;

	}

	private static int editUser(String username, String oldPW, String newPW, String managerPW) throws NoSuchAlgorithmException, IOException {

		int result = validateUser(username, oldPW);

		if(result != 1) {
			return result;
		}else {
			removeLineFromFile("users.txt", username + ":" + encryptionAlgorithms.hashingDados(oldPW) + "\n", managerPW, "mac");
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("users.txt")));
			bw.write(username + ":" + encryptionAlgorithms.hashingDados(newPW) + "\n");

			//			File temp = new File("users.txt");
			//			temp.renameTo(new File("tempUsers.txt"));
			//			BufferedReader br = new BufferedReader(new FileReader(temp));
			//			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("users.txt")));
			//
			//			while(br.ready()) {
			//				String data = br.readLine();
			//				String[] userData = data.split(":");
			//				if(!userData[0].equals(username)) {
			//					bw.write(data);
			//				}else {
			//					bw.write(username + ":" + encryptionAlgorithms.hashingDados(newPW) + "\n");
			//				}
			//			}
			//
			//			temp.delete();
			//
			//			br.close();
			//			bw.close();

			encryptionAlgorithms.atualizaMAC(encryptionAlgorithms.geraMAC(managerPW));
			bw.close();

			return 1;

		}

	}

	private static int removeUser(String user, String pass, String managerPW) throws IOException, NoSuchAlgorithmException {

		int result = validateUser(user, pass);

		if(result != 1) {
			return result;
		}else {
			removeLineFromFile("users.txt", user + ":" + encryptionAlgorithms.hashingDados(pass) + "\n", managerPW, "mac");
			BufferedReader br = new BufferedReader(new FileReader(new File("users.txt")));
			Files.walk(Paths.get("users/" + user))
			.map(Path::toFile)
			.sorted((o1, o2) -> -o1.compareTo(o2))
			.forEach(File::delete);

			while(br.ready()) {
				String[] data = br.readLine().split(":");
				removeLineFromFile("users/" + data[0] + "/trustedUsers.txt", user, managerPW, "assinatura");
			}


			//			File temp = new File("users.txt");
			//			temp.renameTo(new File("tempUsers.txt"));
			//			BufferedReader br = new BufferedReader(new FileReader(temp));
			//			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("users.txt")));
			//
			//			while(br.ready()) {
			//				String data = br.readLine();
			//				String[] userData = data.split(":");
			//				
			//				File tempTrusted = new File("users/" + userData[0] + "/trustedUsers.txt");
			//				tempTrusted.renameTo(new File("users/" + userData[0] + "/tempTrustedUsers.txt"));
			//				BufferedReader btr = new BufferedReader(new FileReader(temp));
			//				BufferedWriter btw = new BufferedWriter(new FileWriter(new File("users/" + userData[0] + "/trustedUsers.txt")));
			//				
			//				
			//				
			//				
			//				if(!userData[0].equals(user)) {
			//					bw.write(data);
			//				}
			//				
			//				btr.close();
			//				btw.close();
			//			}
			//
			//			temp.delete();
			//


			encryptionAlgorithms.atualizaMAC(encryptionAlgorithms.geraMAC(managerPW));
			br.close();

			return 1;

		}
	}


	public static int validateUser(String user, String pass) throws IOException, NoSuchAlgorithmException {

		BufferedReader br = new BufferedReader(new FileReader(new File("users.txt")));

		while(br.ready()) {
			String[] splited = br.readLine().split(":");
			if(splited[0].equals(user)) {
				String tempPass = encryptionAlgorithms.hashingDados(pass);
				if(tempPass.substring(tempPass.indexOf(":")).equals(splited[2])) {
					br.close();
					return 1;
				}

				br.close();
				return -1;
			}
		}

		br.close();
		return 0;

	}

	public static boolean removeLineFromFile(String fileName, String remove, String managerPW, String type) throws IOException {

		File temp = new File(fileName);
		temp.renameTo(new File("temp" + fileName));
		BufferedReader br = new BufferedReader(new FileReader(temp));
		BufferedWriter bw = new BufferedWriter(new FileWriter(new File(fileName)));

		while(br.ready()) {
			String data = br.readLine();
			if(!data.equals(remove)) {
				bw.write(data);
			}
		}

		temp.delete();

		br.close();
		bw.close();

		switch (type) {

		case "mac":

			encryptionAlgorithms.atualizaMAC(encryptionAlgorithms.geraMAC(managerPW));
			return true;

		case "assinatura":

			//faz assinatura (po trusted users file)
			return true;

		default: //nao faz nenhum tipo de encriptacao (qnd queres isto type deve ser null)
			return true;
		}
	}

	/**
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private SecretKey generateKey() throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		return kg.generateKey();
	}

	/**
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private void setKS(String pw) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		ks  = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream("keyStore.jks"), pw.toCharArray());
	}

	/**
	 * 
	 * @return
	 */
	private PrivateKey getPiK(String pw){
		return (PrivateKey) ks.getKey(alias, pw.toCharArray());			
	}

	/**
	 * 
	 * @return
	 */
	private PublicKey getPuK() {
		Certificate cert = ks.getCertificate(alias);
		return cert.getPublicKey();
	}

	/**
	 * 
	 * @param key
	 * @param fileName
	 * @param user
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws IllegalBlockSizeException 
	 */
	private void saveFileKey(SecretKey key, String path) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException {

		//ir buscar o certificado que tem a chave publica e privada
		Cipher c1 = Cipher.getInstance("RSA");
		PublicKey pk = getPuK();
		c1.init(Cipher.WRAP_MODE, pk);
		byte[] wrappedKey = c1.wrap(key);

		File kFile = new File(path);
		kFile.createNewFile();
		FileOutputStream keyOutputFile = new FileOutputStream(kFile);
		keyOutputFile.write(wrappedKey);
		keyOutputFile.close();
	}

	/**
	 * 
	 * @param path
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 * @throws IllegalBlockSizeException 
	 */
	private SecretKey getFileKey(String path) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException {

		File keyFile = new File(path + ".key");
		if(keyFile.exists()) {
			FileInputStream keyFileInput = new FileInputStream(path + ".key");

			byte[] wrappedKey = new byte[keyFileInput.available()];
			Cipher c1 = Cipher.getInstance("RSA");

			keyFileInput.read(wrappedKey);
			PublicKey pk = getPuK();
			c1.init(Cipher.UNWRAP_MODE, pk);
			keyFileInput.close();

			return (SecretKey)c1.unwrap(wrappedKey, "RSA", Cipher.SECRET_KEY);
		}else {
			keyFile.createNewFile();
			SecretKey key = generateKey();
			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, key);

			saveFileKey(key, path);

			return key;
		}	
	}

	/**
	 * 
	 * @param path
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 */
	private boolean verificaSig(String path, String managerPW) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException, IOException, IllegalBlockSizeException {

		File f = new File(path);
		Cipher cInput = Cipher.getInstance("AES");
		SecretKey key = getFileKey(f.getPath());
		FileInputStream fis = new FileInputStream(f);

		cInput.init(Cipher.DECRYPT_MODE, key);

		CipherInputStream cis = new CipherInputStream(fis, cInput);
		StringBuilder sb = new StringBuilder();
		char letra;
		PrivateKey pk = getPiK(managerPW);
		Signature s = Signature.getInstance("MD5withRSA");
		byte[] sig;

		s.initSign(pk);

		//faz update ah signature
		while(cis.available() != 0) {
			if((letra = (char)cis.read()) != '\n') {
				sb.append(letra);
			}else {
				s.update(sb.toString().getBytes());
				sb.setLength(0);
			}
		}

		//Recebe o array de bytes que eh a signature gerada
		sig = s.sign();
		String pathSig = path.substring(0, path.length() - 3);
		f = new File(pathSig);
		fis = new FileInputStream(f);

		//Verifica se as assinaturas sao iguais, se nao entao o ficheiro foi alterado
		if(sig.length == f.length()) {
			for(int i = 0; i < sig.length; i++) {
				if(sig[i] != fis.read()) {
					cis.close();
					fis.close();
					return false;
				}
			}
		}else {
			cis.close();
			fis.close();
			return false;
		}
		cis.close();
		fis.close();
		return true;
	}

	/**
	 * 
	 * @param sig
	 * @param user
	 * @throws IOException
	 */
	private void atualizaSig(byte[] sig, String user) throws IOException {
		File f = new File("users/" + user + "/trustedUsers.txt");
		File sigFile = new File("users/" + user + "/trustedUsers.sig");
		if(sigFile.exists()) {
			sigFile.delete();
		}
		sigFile = new File("users/" + user + "/trustedUsers.sig");
		FileOutputStream newFile = new FileOutputStream(f);
		ObjectOutputStream oos = new ObjectOutputStream(newFile);
		oos.write(sig);
		oos.close();
		newFile.close();			
	}

	/**
	 * 
	 * @param user
	 * @return
	 * @throws InvalidKeyException 
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchPaddingException 
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws IllegalBlockSizeException 
	 */
	private byte[] generateSig(String user, String managerPW) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, IOException, IllegalBlockSizeException {
		File f = new File("users/" + user + "/trustedUsers.txt");
		FileInputStream fis = new FileInputStream(f);
		Cipher c = Cipher.getInstance("AES");
		SecretKey key = getFileKey(f.getPath());
		c.init(Cipher.DECRYPT_MODE, key);
		CipherInputStream cos = new CipherInputStream(fis, c);
		PrivateKey pk = getPiK(managerPW);
		Signature s = Signature.getInstance("MD5withRSA");
		s.initSign(pk);
		char letra;
		StringBuilder sb = new StringBuilder();
		while(cos.available() != 0) {
			if((letra = (char)cos.read()) != '\n') {
				sb.append(letra);
			}else {
				s.update(sb.toString().getBytes());
				sb.setLength(0);
			}
		}
		cos.close();
		return s.sign();			
	}


	private static String presentOptions() {

		StringBuilder sb = new StringBuilder();

		sb.append("\n\n-----------------------------------------------------------------------------\n");
		sb.append("add <username> <password> - adiciona conta de utilizador ao servidor\n");
		sb.append("edit <username> <old password> <new password> - altera a password do utilizador\n");
		sb.append("remove <username> <password> - remove conta de utilizador do servidor\n");
		sb.append("quit - sai do programa\n");
		sb.append("-----------------------------------------------------------------------------\n");

		return sb.toString();
	}
}
