import java.io.*;
import java.util.*;

public class extendedACL{
	public static void main(String[] args) throws FileNotFoundException{
		// user inputs 
		Scanner userInput = new Scanner(System.in);

		System.out.println("EXTENDED ACL");

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

		// sources ip inputs
		File ipFile  = new File(ipFileName);
		Scanner sourceIpInputs = new Scanner(ipFile);

		// ------------------------------------------ ACL FILE INPUTS  ----------------------------------------------------

		// storing permit/ deny from the ACL inputs
		ArrayList<String> permit_deny = new ArrayList<String>();

		// storing all source/destination ip from the ACL inputs 
		ArrayList<String> source_destination_ips = new ArrayList<String>();

		// storing all mask from the ACL inputs 
		ArrayList<String> source_destination_mask = new ArrayList<String>();

		// storing all protocol id from the ACL inputs 
		ArrayList<String> acl_protocol_id = new ArrayList<String>();

		// storing all port id from the ACL inputs 
		ArrayList<String> acl_port_id = new ArrayList<String>();

		// all info of the ACL to check the rules
		ArrayList<String> aclinfo = new ArrayList<String>();
		
		// ------------------------------------------ SOURCE INPUTS  ----------------------------------------------------

		// storing all user source and destination ip inputs 
		ArrayList<String> source_destination_users_Ips = new ArrayList<String>();

		// storing all user source and destination port addr inputs 
		ArrayList<String> source_destination_users_portaddrs = new ArrayList<String>();

		// storing all errors source and destination ips and port addrs
		ArrayList<String> error_source_destination_users_Ips = new ArrayList<String>();

		
		// for ACL inputs
		// this count is used to store source/destination ip (even) and mask (odd)
		int count = 0;
		while(aclInputs.hasNext()){

			// file inputs
			String inputs = aclInputs.next();

			// stroing all info
			aclinfo.add(inputs);

			// taking all the permit and deny and storing both in the arraylist
			if (inputs.equals("permit") || inputs.equals("deny")) {
				permit_deny.add(inputs);
			}

			// add protocol ids
			if (inputs.equals("tcp") || inputs.equals("udp") || inputs.equals("ip")) {
				acl_protocol_id.add(inputs);
			}

			// add port address
			if (inputs.equals("22") || inputs.equals("20") || inputs.equals("21") || inputs.equals("20-21") 
				|| inputs.equals("23")|| inputs.equals("25") || inputs.equals("80") 
				|| inputs.equals("53") || inputs.equals("69") || inputs.equals("161")) {

					acl_port_id.add(inputs);
			}

			// return true if ip is valid other wise check is false (using helper method of the ip)
			boolean check = ipvalid(inputs);
			
			// check is TRUE otherwise dont do anything (IP VALID)
			if (check) {
				// if the count is even means it is add in ip other wise it will add in the mask
				// even and odd because pattern always be like
				// access-list number permit/deny protocol_id source_ip source_mask dest_ip dest_mask port_num eq/range 80/161(never changes) 
				if (count % 2 == 0) {
					source_destination_ips.add(inputs);
				}
				else{
					source_destination_mask.add(inputs);
				}
				count++;
			}
			// if the inputs is any it means they can go anywhere 
			//  source ip --> 0.0.0.0 and destination ip --> 255.255.255.255
			if (inputs.equals("any")) {
				// source ip
				inputs = "0.0.0.0";
				source_destination_ips.add(inputs);

				// destination ips
				inputs = "255.255.255.255";
				source_destination_mask.add(inputs);
			}
		}

		aclInputs.close();

		// For the source IPs
		while(sourceIpInputs.hasNext()){
			// file inputs
			// input1 & input2 are the ip address (source and destination)
			// input3 are the port address
			String input1 = sourceIpInputs.next();
			String input2 = sourceIpInputs.next();
			String input3 = sourceIpInputs.next();

			// if the length is 0 it will add to the array some mistake in ip or port address from the users
			if (input1.trim().length() !=0 && input2.trim().length() !=0 && input3.trim().length() !=0) {
				
				// return true if ip is valid other wise check is false
				boolean checksource = ipvalid(input1);
				boolean checkdest = ipvalid(input2);

				// check is TRUE (IP VALID) otherwise put in the error source ips (IP INVALID)  
				if (checksource && checkdest) {
					source_destination_users_Ips.add(input1);
					source_destination_users_Ips.add(input2);

					if (input3.equals("22") || input3.equals("20") || input3.equals("21") || input3.equals("20-21") 
						|| input3.equals("23")|| input3.equals("25") || input3.equals("80") 
						|| input3.equals("53") || input3.equals("69") || input3.equals("161")) {

						source_destination_users_portaddrs.add(input3);
					}
				}
				else{
					error_source_destination_users_Ips.add(input1);
					error_source_destination_users_Ips.add(input2);
					error_source_destination_users_Ips.add(input3);
				}

			}
			else{
				error_source_destination_users_Ips.add("Missing something in the input file :)");
			}
		}

		sourceIpInputs.close();

		// split source_destination_ips Arraylist into 2 
		// one arraylist with String array which has only source ips (storing string Array in the Arraylist)
		// another arraylist with String array which has only destionation ips (storing string Array in the Arraylist)
		ArrayList<String[]> acl_source_ips = getSourceDestination(source_destination_ips, 0);
		ArrayList<String[]> acl_destination_ips = getSourceDestination(source_destination_ips, 1);

		// split source_destination_mask Arraylist into 2
		// one arraylist with String array which has only source mask only (storing string Array in the Arraylist)
		// another one destionation mask only (storing string Array in the Arraylist)
		ArrayList<String[]> acl_source_mask = getSourceDestination(source_destination_mask, 0);
		ArrayList<String[]> acl_destination_mask = getSourceDestination(source_destination_mask, 1);

		// split source_destination_users_Ips Arraylist into 2 
		// one arraylist with String array which has only users source ips (storing string Array in the Arraylist)
		// another arraylist with String array which has only users destionation ips (storing string Array in the Arraylist)
		ArrayList<String[]> users_source_ips = getSourceDestination(source_destination_users_Ips, 0);
		ArrayList<String[]> users_destination_ips = getSourceDestination(source_destination_users_Ips, 1);
		
		// remove extra protocol which come from the last line in the ACL
		acl_protocol_id.remove(acl_protocol_id.size()-1);

		System.out.println("Checking......... : " );
		System.out.println();
		
		// formated Ips 
		String formatedSIps = "";
		String formatedDIps = "";

		// Error store and print
		String errorname = "";
		String printportocoloerrorcheck = "";
		boolean portocoloerrorcheck = false;
		
		//checking ACL Number and ACL number (First Line) == ACL number (Last Line) 
		if (Integer.parseInt(aclinfo.get(1)) >= 100 && Integer.parseInt(aclinfo.get(1)) <= 199 && Integer.parseInt(aclinfo.get(1)) == Integer.parseInt(aclinfo.get(aclinfo.size()-2))) {

			// checking acl IPS and MASK they should be correct
			if ((acl_source_ips.size() == acl_destination_ips.size()) && (acl_source_mask.size() == acl_destination_mask.size()) && (acl_source_ips.size() == acl_source_mask.size()) && (acl_destination_mask.size() == acl_destination_ips.size())) {

				// loop through the valid user to get packets are deny or permit
				for (int i = 0; i < users_source_ips.size(); i++) {

					// getting formated source and destinations ips
					String formatedsourceip = getFormatedIPs(formatedSIps, users_source_ips, i);
					String formatedDestinationIps = getFormatedIPs(formatedDIps, users_destination_ips, i);

					// loop through ACL STATUS (permit/deny)
					for (int j = 0; j < permit_deny.size(); j++) {

						String aclStatus = permit_deny.get(j).trim();

						// protocol is tcp
						if (acl_protocol_id.get(j).equals("tcp")) {

							// check if the  acl port number should be these if not then print error
							if (acl_port_id.get(j).equals("20-21") || acl_port_id.get(j).equals("20") || acl_port_id.get(j).equals("21") || acl_port_id.get(j).equals("23") || acl_port_id.get(j).equals("22") || 
								acl_port_id.get(j).equals("25") || acl_port_id.get(j).equals("80")) {

								if (source_destination_users_portaddrs.get(i).equals(acl_port_id.get(j)) || acl_port_id.get(j).contains(source_destination_users_portaddrs.get(i))) {
									// status is deny 
									if (aclStatus.equals("deny")) {
										denyAndPrint(i, j, formatedsourceip, formatedDestinationIps, acl_source_ips, acl_destination_ips, acl_source_mask, acl_destination_mask, users_source_ips, users_destination_ips, source_destination_users_portaddrs);
										break;
									}

									// or status is permit
									else{
										permitAndPrint(i, j, formatedsourceip, formatedDestinationIps, acl_source_ips, acl_destination_ips, acl_source_mask, acl_destination_mask, users_source_ips, users_destination_ips, source_destination_users_portaddrs);
										break;
									}
								}
							}
							else{
								portocoloerrorcheck = true;
								printportocoloerrorcheck += "This Protocol " + acl_protocol_id.get(j) + " does not accept this port id " + acl_port_id.get(j);
								break;
							}
						}
						
						// protocol is udp
						else if (acl_protocol_id.get(j).equals("udp")){
							// check if the acl port number should be these if not then print error
							if (acl_port_id.get(j).equals("53") || acl_port_id.get(j).equals("69") || acl_port_id.get(j).equals("161")) {
								
								if (source_destination_users_portaddrs.get(i).equals(acl_port_id.get(j))) {
									
									// status is deny 
									if (aclStatus.equals("deny")) {
										denyAndPrint(i, j, formatedsourceip, formatedDestinationIps, acl_source_ips, acl_destination_ips, acl_source_mask, acl_destination_mask, users_source_ips, users_destination_ips, source_destination_users_portaddrs);
										break;
									}

									// or status is permit
									else{
										permitAndPrint(i, j, formatedsourceip, formatedDestinationIps, acl_source_ips, acl_destination_ips, acl_source_mask, acl_destination_mask, users_source_ips, users_destination_ips, source_destination_users_portaddrs);
										break;
									}

								}
							}
							else{
								portocoloerrorcheck = true;
								printportocoloerrorcheck += "This Protocol " + acl_protocol_id.get(j) + " does not accept this port id " + acl_port_id.get(j);
								break;
							}
						}
						// protocol is ip
						else if (acl_protocol_id.get(j).equals("ip")) {
								// status is deny 
								if (aclStatus.equals("deny")) {
									denyAndPrint(i, j, formatedsourceip, formatedDestinationIps, acl_source_ips, acl_destination_ips, acl_source_mask, acl_destination_mask, users_source_ips, users_destination_ips, source_destination_users_portaddrs);
									break;
								}

								// or status is permit
								else{
									permitAndPrint(i, j, formatedsourceip, formatedDestinationIps, acl_source_ips, acl_destination_ips, acl_source_mask, acl_destination_mask, users_source_ips, users_destination_ips, source_destination_users_portaddrs);
									break;
								}	
						}
						else{
							portocoloerrorcheck = true;
							printportocoloerrorcheck += "This Protocol " + acl_protocol_id.get(j) + " does not accept this port id " + acl_port_id.get(j);
							break;
						}
					}

					// check if there is any error with protocol id and port id 
					if (portocoloerrorcheck) {
						errorname =  printportocoloerrorcheck + "\n";
						showerror(aclFileName, errorname);
						portocoloerrorcheck = false;
						break;
					}
				}

			}
			else{
				errorname = "IPS in the ACL (Soruce/Destination) are incorrect \n";
				showerror(aclFileName, errorname);
			}
		}
		// if the acl number is not bettween 100 and 199 then print error
		else{
			errorname = "Does not match number ACL number or not between 100 to 199 \n";
			showerror(aclFileName, errorname);
		}

		// print error ips in source IP inputs
		printErrorIps(error_source_destination_users_Ips);

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


	// separate the ACL soruce and destination ips from one arraylist to 2 different arraylist
	// separate the ACL soruce and destination mask from one arraylist to 2 different arraylist
	// separate the USER soruce and destination mask from one arraylist to 2 different arraylist
	public static ArrayList<String[]> getSourceDestination(ArrayList<String> source_destination_ips, int index){
		ArrayList<String[]> arr = new ArrayList<String[]>();
		
		// if index is even then it will return source otherwise return destination
		if (index == 0) {
			for (int i=0; i < source_destination_ips.size(); i++) {
				if (i % 2 == 0) {
					String[] sourceIp = source_destination_ips.get(i).split("\\.");
					arr.add(sourceIp);
				}
			}
		}
		else{
			for (int j = 0; j <  source_destination_ips.size(); j++) {
				if (j % 2 != 0) {
					String[] sourceIp = source_destination_ips.get(j).split("\\.");
					arr.add(sourceIp);
				}
			}	
		}
		return arr;
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

	// PRINT THE INVALID IPS (Source and Destination) also print port ids
	public static void printErrorIps(ArrayList<String> errorsourceIps){
		System.out.println();
		System.out.println("---------------------- INVALID SOURCE IPS -----------");
		int count = 1; 
		for (int i = 0; i < errorsourceIps.size(); i++) {
			System.out.print(errorsourceIps.get(i) + "  ");
			if (count % 3 == 0) {
				System.out.println();
			}
			count++;
		}
	}

	// deny statement is to check whether is permit or deny
	public static void denyAndPrint(int i, int j, String formatedsourceip, String formatedDestinationIps, ArrayList<String[]> acl_source_ips, ArrayList<String[]> acl_destination_ips, ArrayList<String[]> acl_source_mask, ArrayList<String[]> acl_destination_mask, ArrayList<String[]> users_source_ips, ArrayList<String[]> users_destination_ips, ArrayList<String> source_destination_users_portaddrs){
		// checking the first number in ip and source
		if (Integer.parseInt(acl_source_ips.get(j)[0]) == Integer.parseInt(users_source_ips.get(i)[0]) && Integer.parseInt(acl_destination_ips.get(j)[0]) == Integer.parseInt(users_destination_ips.get(i)[0])) {

			// checking the second in ip and source if not then error
			if (Integer.parseInt(acl_source_ips.get(j)[1]) == Integer.parseInt(users_source_ips.get(i)[1]) && Integer.parseInt(acl_destination_ips.get(j)[1]) == Integer.parseInt(users_destination_ips.get(i)[1])) {

				// if first and second number match then check for the mask 
				// if mask third number is 0 source and 0 destination (MASK)
				if (Integer.parseInt(acl_source_mask.get(j)[2]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[2]) == 0) {
					// then check the mask fourth number is 0 source and 0 destination (MASK)
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 0)) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_source_ips.get(j)[3]) == Integer.parseInt(users_source_ips.get(i)[3]) && Integer.parseInt(acl_destination_ips.get(j)[3]) == Integer.parseInt(users_destination_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) + " denied");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
					}
					
					// then check the mask fourth number is 255 source and check the mask fourth number is 0 destination (MASK)
					else if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 0)) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_destination_ips.get(j)[3]) == Integer.parseInt(users_destination_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
					}
					
					// then check the mask fourth number is 0 source and check the mask fourth number is 255 destination (MASK)
					else if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255)) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_source_ips.get(j)[3]) == Integer.parseInt(users_source_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
					}
					
					// then check the mask fourth number is 255 source and check the mask fourth number is 255 destination (MASK)
					else if (Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255){
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2])) {
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) + " denied");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
					}
				}
				
				// else if mask third number is 255 source and 0 destination (MASK)
				else if ((Integer.parseInt(acl_source_mask.get(j)[2]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[2]) == 0)) {
					
					// then check the mask fourth number is 255 source and check the mask fourth number is 0 destination (MASK)
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 0)) {
						if (Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_destination_ips.get(j)[3]) == Integer.parseInt(users_destination_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
						else{
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
					}
					
					// check the mask fourth number is 255 source and 255 destination (MASK)
					else if (Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255){
						if (Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2])) {
								System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
							}
							else{
								System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
							}
						}
				}

				// else if mask third number is 0 source and 255 destination (MASK)
				else if ((Integer.parseInt(acl_source_mask.get(j)[2]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[2]) == 255)) {
					
					// then check the mask fourth number is 0 source and check the mask fourth number is 255 destination (MASK)
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255)) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_source_ips.get(j)[3]) == Integer.parseInt(users_source_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
						else{
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
					}
					
					// check the mask fourth number is 255 source and 255 destination (MASK)
					else if (Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255){
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2])) {
							System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
						else{
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
					}
				}
				
				// else mask third number is 255 source and 255 destination (MASK)
				else{
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255)) {
						System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " denied");
					}
					else{
						System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " permitted");
					}
				}
			}
			// error if the first position is not matched
			else{
				System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " denied");
			}
		}
	}

	// permit statement is to check whether is permit or deny (same as deny but reverse the print statements)
	public static void permitAndPrint(int i, int j, String formatedsourceip, String formatedDestinationIps, ArrayList<String[]> acl_source_ips, ArrayList<String[]> acl_destination_ips, ArrayList<String[]> acl_source_mask, ArrayList<String[]> acl_destination_mask, ArrayList<String[]> users_source_ips, ArrayList<String[]> users_destination_ips, ArrayList<String> source_destination_users_portaddrs){
		// checking the first number in ip and source
		if (Integer.parseInt(acl_source_ips.get(j)[0]) == Integer.parseInt(users_source_ips.get(i)[0]) && Integer.parseInt(acl_destination_ips.get(j)[0]) == Integer.parseInt(users_destination_ips.get(i)[0])) {

			// checking the second in ip and source
			if (Integer.parseInt(acl_source_ips.get(j)[1]) == Integer.parseInt(users_source_ips.get(i)[1]) && Integer.parseInt(acl_destination_ips.get(j)[1]) == Integer.parseInt(users_destination_ips.get(i)[1])) {

				// if first and second number match then check for the mask 
				// if mask third number is 0 source and 0 destination (MASK)
				if (Integer.parseInt(acl_source_mask.get(j)[2]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[2]) == 0) {

					// then check the mask fourth number is 0 source and 0 destination (MASK) 
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 0) ) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_source_ips.get(j)[3]) == Integer.parseInt(users_source_ips.get(i)[3]) && Integer.parseInt(acl_destination_ips.get(j)[3]) == Integer.parseInt(users_destination_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) + " permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}

					// then check the mask fourth number is 255 source and check the mask fourth number is 0 destination (MASK)
					else if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 0)) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_destination_ips.get(j)[3]) == Integer.parseInt(users_destination_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  "  permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}

					// then check the mask fourth number is 0 source and check the mask fourth number is 255 destination (MASK)
					else if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255)) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_source_ips.get(j)[3]) == Integer.parseInt(users_source_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  "  permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}
					// check the mask fourth number is 255 source and 255 destination (MASK)
					else if (Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255){
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2])) {
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) + "  permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from "  + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}
				}

				// else if mask third number is 255 source and 0 destination (MASK)
				else if ((Integer.parseInt(acl_source_mask.get(j)[2]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[2]) == 0)) {

					// then check the mask fourth number is 255 source and check the mask fourth number is 0 destination (MASK)
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 0)) {
						if (Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2]) &&
							Integer.parseInt(acl_destination_ips.get(j)[3]) == Integer.parseInt(users_destination_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}

					// check the mask fourth number is 255 source and 255 destination (MASK)
					else if (Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255){
						if (Integer.parseInt(acl_destination_ips.get(j)[2]) == Integer.parseInt(users_destination_ips.get(i)[2])) {
							System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}
				}

				// else if mask third number is 0 source and 255 destination (MASK)
				else if ((Integer.parseInt(acl_source_mask.get(j)[2]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[2]) == 255)) {
					
					// then check the mask fourth number is 0 source and check the mask fourth number is 255 destination (MASK)
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 0 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255)) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2]) && Integer.parseInt(acl_source_ips.get(j)[3]) == Integer.parseInt(users_source_ips.get(i)[3])) {
								System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}

					// check the mask fourth number is 255 source and 255 destination (MASK)
					else if (Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255) {
						if (Integer.parseInt(acl_source_ips.get(j)[2]) == Integer.parseInt(users_source_ips.get(i)[2])) {
							System.out.println((i+1) + ". Packet from "+ formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " permitted");
						}
						else{
							System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +  " denied");
						}
					}
				}

				// else mask third number is 255 source and 255 destination (MASK)
				else{
					if ((Integer.parseInt(acl_source_mask.get(j)[3]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255)) {
						System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " permitted");
					}
					else{
						System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " denied");
					}
				}
			}

			// error if the first number is not matched
			else{
				System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " denied");
			}
		}

		// if the first is not matched then check if the soruce ip is 0.0.0.0 and mask ip is 255.255.255.255 same for the destination
		else{
			if (Integer.parseInt(acl_source_ips.get(j)[0]) == 0 && Integer.parseInt(acl_source_ips.get(j)[1]) == 0 && Integer.parseInt(acl_source_ips.get(j)[2]) == 0 && Integer.parseInt(acl_source_ips.get(j)[3]) == 0 && 
				Integer.parseInt(acl_source_mask.get(j)[0]) == 255 && Integer.parseInt(acl_source_mask.get(j)[1]) == 255 && Integer.parseInt(acl_source_mask.get(j)[2]) == 255 && Integer.parseInt(acl_source_mask.get(j)[3]) == 255 
				||
				Integer.parseInt(acl_destination_ips.get(j)[0]) == 0 && Integer.parseInt(acl_destination_ips.get(j)[1]) == 0 && Integer.parseInt(acl_destination_ips.get(j)[2]) == 0 && Integer.parseInt(acl_destination_ips.get(j)[3]) == 0 &&
				Integer.parseInt(acl_destination_mask.get(j)[0]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[1]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[2]) == 255 && Integer.parseInt(acl_destination_mask.get(j)[3]) == 255) {
					System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " permitted");
			}
			else{
				System.out.println((i+1) + ". Packet from " + formatedsourceip + " To " + formatedDestinationIps + " on port " + source_destination_users_portaddrs.get(i) +   " denied");
			}
		}

	}

}