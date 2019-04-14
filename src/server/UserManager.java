package server;
import java.util.Scanner;

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
				
				

				break;

			case "edit":
				break;

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
	

}
