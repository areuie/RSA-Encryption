package com.za.crypto.rsa.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Set;

public class ServerThread extends Thread {
	private Server server;
	private BufferedReader bufferedReader;
	private PrintWriter printWriter;
	
	public ServerThread(Socket socket, Server server) throws IOException {
		this.server = server;
		this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.printWriter = new PrintWriter(socket.getOutputStream(), true);
	}
	void forwardMessage(String message) {printWriter.println(message); }
}
