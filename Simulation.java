package lista4;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class Simulation {

	public static void main(String[] args) {
		long timeStamp;
		String msg, enc, dec;
		List<BigInteger> factors = new ArrayList<>();
		
		int k = Integer.parseInt(args[0]);
		int d = Integer.parseInt(args[1]);

		timeStamp = System.currentTimeMillis();
		factors = RSA.generateKeys(k, d);
		System.out.println("Generation time: " + (System.currentTimeMillis() - timeStamp));

		msg = Simulation.readFile("msg.txt");
		timeStamp = System.currentTimeMillis();
		String cipher = RSA.encrypt(msg);
		System.out.println("Encryption time: " + (System.currentTimeMillis() - timeStamp));
		Simulation.save(cipher, "enc.txt");

		enc = Simulation.readFile("enc.txt");
		timeStamp = System.currentTimeMillis();
		dec = RSA.decrypt(enc);
		System.out.println("Decryption time: " + (System.currentTimeMillis() - timeStamp));
		Simulation.save(dec, "dec.txt");

		enc = Simulation.readFile("enc.txt");
		timeStamp = System.currentTimeMillis();
		dec = RSA.decryptCRT(k, enc, factors);
		System.out.println("CRT Decryption time: " + (System.currentTimeMillis() - timeStamp));
		Simulation.save(dec, "decCRT.txt");
		
		System.exit(0);
	}

	public static String readFile(String filename) {
		String msg = null;

		try {
			msg = new String(Files.readAllBytes(Paths.get(filename)),
					StandardCharsets.UTF_8);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return msg;
	}

	public static void save(String text, String filename) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(filename, "UTF-8");
			writer.print(text);
			writer.close();
		} catch (FileNotFoundException | UnsupportedEncodingException ex) {
			ex.printStackTrace();
		}
	}
}
