package server;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class UserManager {

	public static void main(String[] args){

		try(Scanner sc = new Scanner(System.in)){


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
						int result = editUser(input[1], input[2], input[3], managerPW);
						
						if(result == 0) {
							System.out.println("Este utilizador nao existe. Assim, vai ser criada uma conta com este username e password\n");
						}else if(result == 1) {
							System.out.println("Password atualizada com sucesso\n");
						} else {
							System.out.println("Passe incorreta\n");
						}
						
						break;

					case "remove":
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
		bw.write(encryptionAlgorithms.hashingDados(username + ":" + password) + "\n");



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
			File temp = new File("users.txt");
			temp.renameTo(new File("tempUsers.txt"));
			BufferedReader br = new BufferedReader(new FileReader(temp));
			BufferedWriter bw = new BufferedWriter(new FileWriter(new File("users.txt")));
			
			while(br.ready()) {
				String data = br.readLine();
				String[] userData = data.split(":");
				if(!userData[0].equals(username)) {
					bw.write(data);
				}else {
					bw.write(username + ":" + encryptionAlgorithms.hashingDados(newPW));
				}
			}
			
			temp.delete();
			
			br.close();
			bw.close();
			
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