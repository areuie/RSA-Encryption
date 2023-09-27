package com.za.crypto.rsa.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.IntStream;

import javax.json.Json;
import javax.json.JsonObject;

public class RSAHelper {
	static BigInteger calculateD(BigInteger phi, BigInteger n, BigInteger e) { return e.modInverse(phi); }
	static BigInteger calculatePhi(BigInteger p, BigInteger q) {
		return p.subtract(BigInteger.valueOf(1)).multiply(q.subtract(BigInteger.valueOf(1)));
	}
	static BigInteger[] encryptMessage(String username, String otherPartyUsername, String message, BigInteger e, BigInteger n) {
		System.out.print("["+username+"]: encrypt w/ "+ otherPartyUsername + "'s public key ==> ");
		String[] values = message.split(" ");
		BigInteger[] returnValues = new BigInteger[values.length];
		//encryption
		IntStream.range(0, values.length).forEach(i ->
			returnValues[i] = BigInteger.valueOf(Integer.parseInt(values[i])).modPow(e, n)
		);
		System.out.println("c <congruent> m^e mod n = "+Arrays.toString(returnValues));
		System.out.println("["+username+"]: send ciphertext c = "+Arrays.toString(returnValues));
		return returnValues;
	}
	static BigInteger[] decryptMessage(String username, BigInteger[] c, BigInteger d, BigInteger n) {
		System.out.println("["+username+"]: recieve ciphertext c = " + Arrays.toString(c));
		System.out.print("["+username+"]: decrypt w/ my private key d = " + d + " & obtain ascii ");
		
		BigInteger[] returnValues = new BigInteger[c.length];
		//decryption using c^d mod n
		IntStream.range(0, c.length).forEach(i ->
				returnValues[i] = c[i].modPow(d, n)
		);
		System.out.println("m <congruent> c^d mod n = " + Arrays.toString(returnValues));
		return returnValues; //returns the ascii of the decrypted characters
	}
	static void handleGenerateKeys(BufferedReader br, StringWriter sw, Client client) throws IOException {
		handleInput(br, sw, client);
		//calculating and setting the private key
		client.setD(RSAHelper.calculateD(client.getPhi(), client.getN(), client.getE()));
		System.out.print("[" + client.getUsername() + "]: d*"+ client.getE() + " <congruent> 1 mod " + client.getPhi() + " => d = "+ client.getD());
		//sending a json message indicating what the public key is to the other client
		Json.createWriter(sw).writeObject(Json.createObjectBuilder()
				.add("name", client.getUsername())
				.add("e", client.getE().toString())
				.add("n", client.getN().toString())
				.build());
		client.getPrintWriter().println(sw);
		System.out.println("My public key (n, e) = (" + client.getN()+", " + client.getE() + ") | my private key d = " + client.getD());
		//make sure that all the values are initialized before readying
		if (client.getN() != null && client.getE() != null && client.getEncryptN() != null && client.getEncryptE() != null) {
			System.out.println("[System]: ready to send and recieve messages");
		}
	}
	private static void handleInput(BufferedReader br, StringWriter sw, Client client) throws IOException {
		boolean flag = true;
		BigInteger p = new BigInteger("0"), q = new BigInteger("0");
		//keeps on prompting until input is correct
		while (flag) {
			System.out.println("[System]: enter username and 2 primes (where p != q), seperated by space");
			String[] values = br.readLine().split(" ");
			//user input and is initialized
			client.setUsername(values[0]);
			p = new BigInteger(values[1]);
			q = new BigInteger(values[2]);
			if (!p.equals(q) && isPrime(p) && isPrime(q)) flag = false; //correct format
			else System.out.println("[System]: incorrect input, p and q must be distinct primes.");
		}
		//setting N
		client.setN(p.multiply(q));
		System.out.print("["+ client.getUsername() +"]: p*q = "+ client.getN());
		
		//first calculating Phi
		client.setPhi(RSAHelper.calculatePhi(p, q));
		System.out.println(" | phi(n) = (p-1)*(q-1) = "+ client.getPhi());
		
		//user input again,choosing the public exponent e (must be an element in set 1 to phi(n)-1 )
		while(!flag) {
			System.out.print("[System]:   public exponent e from set {1, 2, 3, ..., phi(n)-1}");
			System.out.println("where inverse of e exists eg, gcd(e, phi(n)) = 1");
			BigInteger input = new BigInteger(br.readLine());
			if (isRelativelyPrime(input, client.getPhi()) && input.compareTo(new BigInteger("1")) >= 0 && input.compareTo(client.getPhi().subtract(new BigInteger("1"))) <= 0) {
				client.setE(input);
				flag = true;
			}
		}
		
	}
	//sends a message to the other user
	static void handleSendMessage(BufferedReader bufferedReader, StringWriter stringWriter, Client client) throws IOException {
		String message = bufferedReader.readLine();
		if (client.getOtherPartyUsername() != null) { //if the other party exists then send the message
			StringBuffer asciiMessage = new StringBuffer(); //reads user input
			IntStream.range(0, message.length()).forEach(x ->
					asciiMessage.append(RSAHelper.characterToAscii(message.charAt(x)) + " ")
			);
			System.out.println("[" +client.getUsername()+ "]:" + " map char to ascii & obtain m = " + asciiMessage.toString());
			BigInteger[] m = RSAHelper.encryptMessage(client.getUsername(), client.getOtherPartyUsername(), asciiMessage.toString(), client.getEncryptE(), client.getEncryptN());
			
			StringBuffer mString = new StringBuffer();
			IntStream.range(0, m.length).forEach(x -> //iterating through each index in the encrypted message and adding it to the string buffer
				mString.append(m[x].toString() + " ")
			);
			stringWriter = new StringWriter();
			//create a json file to be sent over
			Json.createWriter(stringWriter).writeObject(Json.createObjectBuilder()
				.add("name", client.getUsername())
				.add("c", mString.toString().trim())
				.build()
			);
			client.getPrintWriter().println(stringWriter); //using the client to send the stringWriter
		}
	}
	
	static void handleReceivePublicKey(JsonObject jsonObject, Client client) {
		client.setEncryptE(new BigInteger(jsonObject.getString("e")));
		client.setEncryptN(new BigInteger(jsonObject.getString("n")));
		client.setOtherPartyUsername(jsonObject.getString("name")); //fetching the username of the other party
		System.out.println("[System]: "+ client.getOtherPartyUsername() + "'s public key (n, e) = (" + jsonObject.getString("n") + ", " + jsonObject.getString("e") + ")");
		if(client.getN() != null && client.getE() != null && jsonObject.getString("n") != null) {
			System.out.println("[System]: ready to send & recieve messages");
		} else if (client.getN() != null && client.getE() == null) System.out.println("[System]: pick public # e");
		else if (client.getN() == null && client.getE() == null) System.out.println("[System]: enter username, & 2 distinct primes (p, q), seperated by space");
	}
	
	static void handleReceiveMessage(JsonObject jsonObject, Client client) {
		String[] values = jsonObject.getString("c").split(" ");
		BigInteger[] c = new BigInteger[values.length];
		//inserting the incoming cyphertext into BigInteger variable c
		IntStream.range(0, values.length).forEach(i ->
			c[i] = new BigInteger(values[i])
		);
		BigInteger[] m = RSAHelper.decryptMessage(client.getUsername(), c, client.getD(), client.getN());
		System.out.print("[" + client.getUsername() + "]: map ascii to char and obtain ");
		for(int x = 0; x < m.length; x++) System.out.print(RSAHelper.asciiToCharacter(m[x].intValue()));
		System.out.print("\n[" + client.getOtherPartyUsername() + "]: ");
		for(int x = 0; x < m.length; x++) System.out.print(RSAHelper.asciiToCharacter(m[x].intValue()));
		System.out.println();
	}
	
	static boolean isPrime(BigInteger number) {return number.isProbablePrime(1000); }
	//if they are prime in relation to each other
	static boolean isRelativelyPrime(BigInteger e, BigInteger phi) {return e.gcd(phi).intValue() == 1;}
	static int characterToAscii(char character) {return (int)character;}
	static char asciiToCharacter(int ascii) {return (char) ascii;}
}
