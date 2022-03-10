import java.io.*;
import java.util.*;

public class standardACL{
	public static void main(String[] args) throws FileNotFoundException{
		// user inputs 
		Scanner userInput = new Scanner(System.in);

		// empty print
		System.out.println();

		// taking ACL file
		System.out.print("Reading a ACL File input[in .txt format]: " );
		String aclFileName = userInput.nextLine().trim();

		// taking source IPs File
		System.out.print("Reading a Source IPs File input[in .txt format]: " );
		String ipFileName = userInput.nextLine().trim();

		// empty print
		System.out.println();

		// standard acl inputs 
		File firstFile  = new File(aclFileName);
		Scanner aclInputs = new Scanner(firstFile);

		// sources ip inputs to check with ACL 
		File ipFile  = new File(ipFileName);
		Scanner sourceIpInputs = new Scanner(ipFile);

		// ------------------------------------------ ACL FILE INPUTS  ----------------------------------------------------

		// storing permit/ deny from the ACL inputs
		ArrayList<String> permit_deny = new ArrayList<String>();

		// storing all ip from the ACL inputs (storing string Array in the Arraylist)
		ArrayList<String[]> ips = new ArrayList<String[]>();

		// storing all mask from the ACL inputs (storing string Array in the Arraylist)
		ArrayList<String[]> mask = new ArrayList<String[]>();

		// all info of the ACL
		ArrayList<String> aclinfo = new ArrayList<String>();
		
		// ------------------------------------------ SOURCE INPUTS  ----------------------------------------------------
		
		// storing all source ip inputs (storing string Array in the Arraylist)
		ArrayList<String[]> sourceIps = new ArrayList<String[]>();

		// storing all errors source ip
		ArrayList<String> errorsourceIps = new ArrayList<String>();

		// for ACL inputs
		int count = 0;

		while(aclInputs.hasNext()){
			// file inputs
			String inputs = aclInputs.next();

			aclinfo.add(inputs);

			// taking all the permit and deny and storing both in the arraylist
			if (inputs.equals("permit") || inputs.equals("deny")) {
				permit_deny.add(inputs);
			}

			// return true if ip is valid other wise check is false (using helper method of the ip)
			boolean check = ipvalid(inputs);
			
			// check is TRUE otherwise dont do anything (IP VALID)
			if (check) {
				// split ip and save in Array save ip 
				String[] arrayip = inputs.split("\\.");

				// if the count is even means it is add in ip other wise it will add in the mask
				// even and odd because pattern always be like
				// access-list number permit/deny source ip mask (never changes) 
				if (count%2 == 0) {
					ips.add(arrayip);
				}
				else{
					mask.add(arrayip);
				}

				count++;
			}

			// if the inputs is any it means they can go anywhere 
			//  source ip --> 0.0.0.0 and destination ip --> 255.255.255.255
			if (inputs.equals("any")) {
				// source ip
				inputs = "0.0.0.0";
				String[] sourceIp = inputs.split("\\.");
				ips.add(sourceIp);

				// destination ips
				inputs = "255.255.255.255";
				String[] destinationIp = inputs.split("\\.");
				mask.add(destinationIp);
			}
		}

		aclInputs.close();

		// For the source IPs
		while(sourceIpInputs.hasNext()){
			// file inputs
			String inputs = sourceIpInputs.next();

			// return true if ip is valid other wise check is false
			boolean check = ipvalid(inputs);

			// check is TRUE (IP VALID) otherwise put in the error source ips (IP INVALID)  
			if (check) {
				// split ip and save in Array save ip 
				String[] arrayIpValid = inputs.split("\\.");
				sourceIps.add(arrayIpValid);
			}
			else{
				errorsourceIps.add(inputs);
			}
		}

		sourceIpInputs.close();

		System.out.println("Checking.......... : " );
		System.out.println();

		// formated Ips 
		String formatedIps = "";
		
		// Error store and print
		String errorname = "";

		if (Integer.parseInt(aclinfo.get(1)) >= 1 && Integer.parseInt(aclinfo.get(1)) <= 99 && Integer.parseInt(aclinfo.get(1)) == Integer.parseInt(aclinfo.get(aclinfo.size()-2))) {

			// checking acl IPS and MASK they should be correct
			if ((ips.size() == mask.size())) {

				// loop through the valid user to get packets are deny or permit
				for (int i = 0; i < sourceIps.size(); i++) {

					// sending string and source IPs and index number so that we can get the formated ip
					String ip = getFormatedIPs(formatedIps, sourceIps, i);

					// ACL status either permit/deny
					for (int j = 0; j < permit_deny.size(); j++) {

						String aclStatus = permit_deny.get(j).trim();

						// check deny in ACL
						if (aclStatus.equals("deny")) {

							// checking the first number in ip and source
							if (Integer.parseInt(ips.get(j)[0]) == Integer.parseInt(sourceIps.get(i)[0])) {

								// checking the second in ip and source
								if (Integer.parseInt(ips.get(j)[1]) == Integer.parseInt(sourceIps.get(i)[1])) {

									// if first and second number match then check for the mask 
									// if mask third number is 0
									if (Integer.parseInt(mask.get(j)[2]) == 0) {

										// then check the mask fourth number is 0
										if (Integer.parseInt(mask.get(j)[3]) == 0) {

											if (Integer.parseInt(ips.get(j)[2]) == Integer.parseInt(sourceIps.get(i)[2]) && Integer.parseInt(ips.get(j)[3]) == Integer.parseInt(sourceIps.get(i)[3])) {
												System.out.println((i+1) + ". Packet from "+ ip + " denied");
												break;  
											}
											else{
												System.out.println((i+1) + ". Packet from " + ip + " permitted");
												break;
											}
										}

										// check the mask fourth number is 255
										else{

											if (Integer.parseInt(ips.get(j)[2]) == Integer.parseInt(sourceIps.get(i)[2])) {
												System.out.println((i+1) + ". Packet from "+ ip + " denied");
												break;  
											}
											else{
												System.out.println((i+1) + ". Packet from " + ip + " permitted");
												break;
											}
										}
									}

									// else mask third number is 255
									else{

										// then check the mask fourth number is 0
										if (Integer.parseInt(mask.get(j)[3]) == 0) {
											if (Integer.parseInt(ips.get(j)[3]) == Integer.parseInt(sourceIps.get(i)[3])) {
												System.out.println((i+1) + ". Packet from "+ ip + " denied");
												break;  
											}
											else{
												System.out.println((i+1) + ". Packet from " + ip + " permitted");
												break;
											}
										}

										// check the mask fourth number is 255
										else{
											System.out.println((i+1) + ". Packet from "+ ip + " denied");
											break;
										}
									}
								}
							}
						}
						// check permit in ACL
						else {

							// checking the first number in ip and source
							if (Integer.parseInt(ips.get(j)[0]) == Integer.parseInt(sourceIps.get(i)[0])) {

								// checking the second in ip and source
								if (Integer.parseInt(ips.get(j)[1]) == Integer.parseInt(sourceIps.get(i)[1])) {

									// if first and second number match then check for the mask 
									// if mask third number is 0
									if (Integer.parseInt(mask.get(j)[2]) == 0) {

										// then check the mask fourth number is 0
										if (Integer.parseInt(mask.get(j)[3]) == 0) {

											if (Integer.parseInt(ips.get(j)[2]) == Integer.parseInt(sourceIps.get(i)[2]) && Integer.parseInt(ips.get(j)[3]) == Integer.parseInt(sourceIps.get(i)[3])) {
												System.out.println((i+1) + ". Packet from " + ip + " permitted");
												break;  
											}
											else{
												System.out.println((i+1) + ". Packet from "+ ip + " denied");
												break;
											}
										}

										// check the mask fourth number is 255
										else{
											if (Integer.parseInt(ips.get(j)[2]) == Integer.parseInt(sourceIps.get(i)[2])) {
												System.out.println((i+1) + ". Packet from " + ip + " permitted");
												break;  
											}
											else{
												System.out.println((i+1) + ". Packet from "+ ip + " denied");
												break;
											}
										}
									}
									// else mask third number is 255
									else{

										// then check the mask fourth number is 0
										if (Integer.parseInt(mask.get(j)[3]) == 0) {

											if (Integer.parseInt(ips.get(j)[3]) == Integer.parseInt(sourceIps.get(i)[3])) {
												System.out.println((i+1) + ". Packet from " + ip + " permitted");
												break;  
											}
											else{
												System.out.println((i+1) + ". Packet from "+ ip + " denied");
												break;
											}
										}
										// check the mask fourth number is 255
										else{
											System.out.println((i+1) + ". Packet from "+ ip + " denied");
											break;
										}
									}
								}

								// checking the second in ip and source is not matched
								else {
									System.out.println((i+1) + ". Packet from "+ ip + " denied");
									break;
								}
							}

							else{
								if (Integer.parseInt(ips.get(j)[0]) == 0 && Integer.parseInt(mask.get(j)[0]) == 255 && Integer.parseInt(ips.get(j)[1]) == 0 && Integer.parseInt(mask.get(j)[1]) == 255 && Integer.parseInt(ips.get(j)[2]) == 0 && Integer.parseInt(mask.get(j)[2]) == 255 && Integer.parseInt(ips.get(j)[3]) == 0 && Integer.parseInt(mask.get(j)[3]) == 255) {
									System.out.println((i+1) + ". Packet from " + ip + " permitted");
									break;
								}
								else{
									System.out.println((i+1) + ". Packet from "+ ip + " denied");
									break;
								}
							}
						}
					}//end of the second for loop
				}// end of the first for loop
			}
			else{
				errorname = "IPS in the ACL (Soruce/Destination) are incorrect \n";
				showerror(aclFileName, errorname);
			}
		}
		else{
			errorname = "Does not match number ACL number or not between 1 to 99 \n";
			showerror(aclFileName, errorname);
		}

		// print error ips in source IP inputs
		printErrorIps(errorsourceIps);

	}// end of the main method 

	// checking with the helper method if IP valid or not
	public static Boolean ipvalid(String ip){
		// IP regex taken from the given citation
		// “Validate an IP address using regular expressions in Java,” CodeSpeedy, 23-Dec-2020. 
		// [Online]. Available: https://www.codespeedy.com/validate-an-ip-address-using-regular-expressions-in-java/. 
		// [Accessed: 05-Mar-2022]. 
		String ipcheck = "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])" + "\\." 
		+ "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])" + "\\." 
		+ "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])" + "\\." 
		+ "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])";

		boolean check = false;
		if (ip.matches(ipcheck)) {
			check = true;
		}
		return check;
	}

	// this method is used to formated ips and return string 
	public static String getFormatedIPs(String formatedIps, ArrayList<String[]> sourceIps, int index){
		for (int i = 0; i < sourceIps.get(index).length; i++) {
			formatedIps = formatedIps + sourceIps.get(index)[i];
			if (i < sourceIps.get(index).length-1) {
				formatedIps += ".";
			} 
		}
		return formatedIps;
	}

	// PRINT THE INVALID IPS
	public static void printErrorIps(ArrayList<String> errorsourceIps){
		System.out.println();
		System.out.println("---------------------- INVALID SOURCE IPS -----------");
		for (int i = 0; i < errorsourceIps.size(); i++) {
			System.out.println(errorsourceIps.get(i));
		}
	}

	// showing errors in the ACL 
	public static void showerror(String aclFileName, String errorname)throws FileNotFoundException{
		File firstFile2  = new File(aclFileName);
		Scanner aclInputs2 = new Scanner(firstFile2);
		System.out.println(errorname);
		while(aclInputs2.hasNext()){
			System.out.println(aclInputs2.nextLine());
		}
		aclInputs2.close();
	}
}
