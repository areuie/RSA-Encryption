package com.za.crypto.rsa.client;

import java.io.BufferedReader;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

import javax.json.Json;
import javax.json.JsonObject;

public class ClientThread extends Thread {
	private BufferedReader reader;
	private Client client;
	
	public ClientThread(Socket socket, Client client) throws IOException {
		this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		this.client = client;
	}
	
	public void run() {
		while (true) {
			JsonObject jsonObject = Json.createReader(reader).readObject();
			if (jsonObject.containsKey("e")) RSAHelper.handleReceivePublicKey(jsonObject, client);
			else if (jsonObject.containsKey("c")) RSAHelper.handleReceiveMessage(jsonObject, client);
		}
	}
}
