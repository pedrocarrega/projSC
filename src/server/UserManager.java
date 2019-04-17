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
