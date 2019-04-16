package server;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class UserManager {

	public static void main(String[] args) {

		Scanner sc = new Scanner(System.in);

		while(true) {

			//apresentar opcoes
			System.out.println(presentOptions());
			//input
			String[] input = sc.nextLine().split(" ");

			switch (input[0]) {
			
			case "add":
				if(addUser(input[1] , input[2], args[0])) {
					System.out.println("User adicionado com sucesso");
				}else {
					System.out.println("Username j� est� em uso");
				}
				break;

			case "edit":
				if(editUser(input[1], input[2], input[3], args[0])) {
					System.out.println("Password atualizada com sucesso");
				}else {
					System.out.println("Dados atuais incorretos, tente novamente");
				}

			case "remove":
				break;

			case "quit":
				sc.close();
				System.exit(0); //fecha o programa

			default:
				System.out.println("Comando invalido, por favor volte a inserir o comando\n\n\n");

				break;
			}
		}



	}

	private static String presentOptions() {

		StringBuilder sb = new StringBuilder();

		sb.append("-----------------------------------------------------------------------------\n");
		sb.append("add <username> <password> - adiciona conta de utilizador ao servidor\n");
		sb.append("edit <username> <old password> <new password> - altera a password do utilizador\n");
		sb.append("remove <username> <password> - remove conta de utilizador do servidor\n");
		sb.append("quit - sai do programa\n");
		sb.append("-----------------------------------------------------------------------------\n");

		return sb.toString();
	}
	
	/**
	 * Devolve uma linha no formato proposto mas com a palavra pass depois do hash j� com salt
	 * @param userData formato = username:password
	 * @throws NoSuchAlgorithmException 
	 */
	private static String hashingDados(String userData) throws NoSuchAlgorithmException {
		Random rnd = new Random();
		int salt = rnd.nextInt();
		String[] splitted = userData.split(":");
		String nPW = salt + splitted[2];
		MessageDigest md = MessageDigest.getInstance("SHA");
		byte[] hashed = md.digest(nPW.getBytes());
		String pwHashed = new String(hashed);
		return splitted[0] + ":" + salt + ":" + pwHashed;
	}
	
	private static boolean addUser(String username, String password, String managerPW) {
		File f = new File("users.txt");
		
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(f.getName()));
			BufferedReader br = new BufferedReader(new FileReader(f.getName()));
			String linha;
			
			while((linha = br.readLine()) != null) {
				String[] lineSplitted = linha.split(":");
				if(lineSplitted[0].equals(username)) {
					bw.close();
					br.close();
					return false;
				}
			}
			bw.write(hashingDados(username + ":" + password) + "\n");
			bw.close();
			br.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		atualizaMAC(geraMAC(managerPW));
		return true;
	}
	
	private static boolean editUser(String username, String oldPW, String newPW, String managerPW) {
		File f = new File("users.txt");
		
		try {
			BufferedReader br = new BufferedReader(new FileReader(f.getName()));
			String linha;
			while((linha = br.readLine()) != null) {
				String[] lineSplitted = linha.split(":");
				if(lineSplitted[0].equals(username)) {
					String dadosHashed = hashingDados(username + ":" + oldPW);
					if(dadosHashed.equals(linha)) {
						File tempFile = new File("usersTemp.txt");
						BufferedWriter bw = new BufferedWriter(new FileWriter(tempFile.getName()));
						//String currentLine;
						br.reset();
						while((linha = br.readLine()) != null) {
							if(!linha.equals(username)) {
								bw.write(linha);
							}
						}
						bw.close();
						br.close();
						atualizaMAC(geraMAC(managerPW));
						return true;
					}
				}
			}
			br.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
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
	
	private static byte[] geraMAC(String managerPW) {
		byte[] salt = {(byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52, 
				(byte) 0x3e, (byte) 0xea, (byte) 0xf2};
		PBEKeySpec keySpec	= 	new	PBEKeySpec(managerPW.toCharArray(), salt, 20);  
		SecretKeyFactory kf;
		SecretKey key;
		Mac mac = null;
		File f = new File("users.txt");
		try {
			mac	= Mac.getInstance("HmacSHA1");
			kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
			key = kf.generateSecret(keySpec);
			mac.init(key);
			
			BufferedReader br = new BufferedReader(new FileReader(f.getName()));
			String linha;
			while((linha = br.readLine()) != null) {
				mac.update(linha.getBytes());
			}
			br.close();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return mac.doFinal();
	}
	
	private static void atualizaMAC(byte[] mac) {
		try {
			FileOutputStream fos = new FileOutputStream("mac1.txt");
			ObjectOutputStream	oos	= new ObjectOutputStream(fos);
			oos.write(mac);
			oos.close();
			fos.close();
			File file = new File("mac1.txt");
			file.renameTo(new File("mac.txt"));
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}