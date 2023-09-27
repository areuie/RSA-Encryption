package com.za.crypto.rsa.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client {
	//initalize usernames
	private String username = null;
	private String otherPartyUsername = null;
	private BigInteger n = null;
	private BigInteger encryptN = null;
	private BigInteger phi = null;
	private BigInteger e = null;
	private BigInteger encryptE = null;
	private BigInteger d = null;
	private PrintWriter printWriter;
	
	public static void main(String[] args) throws UnknownHostException, IOException{
		Client client = new Client();
		Socket socket = new Socket("localhost", 4444);
		//instantiate a new client thread and start it
		new ClientThread(socket, client).start();
		
		client.printWriter = new PrintWriter(socket.getOutputStream(), true);
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
		StringWriter stringWriter = new StringWriter();
		//handles key generation
		RSAHelper.handleGenerateKeys(bufferedReader, stringWriter, client);
		//handles sending messages
		while(true) RSAHelper.handleSendMessage(bufferedReader,  stringWriter, client);

	}
	public BigInteger getE() { return e; }
	public void setE(BigInteger e) {this.e = e;}
	
	public PrintWriter getPrintWriter() { return printWriter; }
	public void setPrintWriter(PrintWriter printWriter) {this.printWriter = printWriter;}
	
	public BigInteger getEncryptN() {return encryptN;}
	public BigInteger getEncryptE() {return encryptE; }
	
	public void setD(BigInteger d) {this.d = d;}
	public BigInteger getD() {return d;}
	
	public void setN(BigInteger n) {this.n = n;}
	public BigInteger getN() {return n;}
	
	public BigInteger getPhi() {return phi;}
	public void setPhi(BigInteger phi) {this.phi = phi;}
	
	public String getUsername() {return username;}
	public void setUsername(String username) {this.username = username;}
	
	public String getOtherPartyUsername() {return otherPartyUsername; }
	public void setOtherPartyUsername(String otherPartyUsername) {this.otherPartyUsername = otherPartyUsername;}
	
	public void setEncryptE(BigInteger encryptE) {this.encryptE = encryptE;}
	public void setEncryptN(BigInteger encryptN) {this.encryptN = encryptN;}
	

}
