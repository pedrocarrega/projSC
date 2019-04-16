package server;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class UserManager {

	public static void main(String[] args) throws InvalidKeyException, IOException {

		Scanner sc = new Scanner(System.in);
		String managerPW = sc.nextLine();
		
		if(encryptionAlgorithms.validMAC(managerPW)) {

			while(true) {

				//apresentar opcoes
				System.out.println(presentOptions());
				//input
				String[] input = sc.nextLine().split(" ");

				switch (input[0]) {

				case "add":
					if(addUser(input[1] , input[2], managerPW)) {
						System.out.println("User adicionado com sucesso");
					}else {
						System.out.println("Username ja esta em uso");
					}
					break;

				case "edit":
					if(editUser(input[1], input[2], input[3], managerPW)) {
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
		}else {
			sc.close();
			throw new InvalidKeyException("INVALID PASSWORD!!!");
		}
	}


	private static boolean addUser(String username, String password, String managerPW) {

		
		try (BufferedWriter bw = new BufferedWriter(new FileWriter(new File("users.txt")));
				BufferedReader br = new BufferedReader(new FileReader(new File("users.txt")))){
			
			String linha;

			while((linha = br.readLine()) != null) {
				String[] lineSplitted = linha.split(":");
				if(lineSplitted[0].equals(username)) {
					return false;
				}
			}
			bw.write(encryptionAlgorithms.hashingDados(username + ":" + password) + "\n");
			
		

		encryptionAlgorithms.atualizaMAC(encryptionAlgorithms.geraMAC(managerPW));
		return true;
		
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static boolean editUser(String username, String oldPW, String newPW, String managerPW) {

		try (BufferedReader br = new BufferedReader(new FileReader(new File("users.txt")))){
			
			String linha;
			while((linha = br.readLine()) != null) {
				String[] lineSplitted = linha.split(":");
				if(lineSplitted[0].equals(username)) {
					String dadosHashed = encryptionAlgorithms.hashingDados(username + ":" + oldPW);
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
						encryptionAlgorithms.atualizaMAC(encryptionAlgorithms.geraMAC(managerPW));
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
}
