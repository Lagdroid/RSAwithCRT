package lista4;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class RSA {

	public static final String PUBLIC = "public.txt";
	public static final String PRIVATE = "private.txt";
	
	public static List<BigInteger> generateKeys(int k, int l) {
		BigInteger n = BigInteger.ONE;
		BigInteger phi = BigInteger.ONE;
		BigInteger e = BigInteger.ONE;
		BigInteger d = BigInteger.ONE;
		
		List<BigInteger> factors = new ArrayList<>();
		
		ExecutorService executor = Executors.newFixedThreadPool(k);
		List<Future<BigInteger>> primes = new ArrayList<Future<BigInteger>>();

		Callable<BigInteger> generator = new PrimesGenerator(l);
		for (int i = 0; i < k; i++) {
			Future<BigInteger> number = executor.submit(generator);
			primes.add(number);
		}
		
        for(Future<BigInteger> num : primes){
            try {
            	BigInteger prime = num.get();
                n = n.multiply(prime);
                phi = phi.multiply(prime.subtract(BigInteger.ONE));
            	factors.add(prime);
            } catch (InterruptedException | ExecutionException ex) {
                ex.printStackTrace();
            }
        }

		do {
			e = new BigInteger(phi.bitLength(), new SecureRandom());
		} while (phi.gcd(e).intValue() > 1 || e.compareTo(BigInteger.ONE) < 0 || e.compareTo(phi) > 0);
		
		d = e.modInverse(phi);	
		RSA.savePublicKey(n, e, PUBLIC);
		RSA.savePrivateKey(n, d, PRIVATE);
		executor.shutdown();
		
		return factors;
	}
	
	private static void savePublicKey(BigInteger n, BigInteger e, String file) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(file, "UTF-8");
			writer.println(e);
			writer.println(n);

			writer.close();
		} catch (FileNotFoundException | UnsupportedEncodingException ex) {
			ex.printStackTrace();
		}
	}
	
	private static void savePrivateKey(BigInteger n, BigInteger d, String file) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(file, "UTF-8");
			writer.println(d);
			writer.println(n);
			
			writer.close();
		} catch (FileNotFoundException | UnsupportedEncodingException ex) {
			ex.printStackTrace();
		}
	}
	
	private static BigInteger[] readPublicKey(String file) {
		BigInteger[] publicKey = new BigInteger[2];
		
		try(BufferedReader br = new BufferedReader(new FileReader(file))) {
		    publicKey[0] = new BigInteger(br.readLine());
		    publicKey[1] = new BigInteger(br.readLine());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return publicKey;
	}
	
	private static BigInteger[] readPrivateKey(String file) {
		BigInteger[] privateKey = new BigInteger[2];
		
		try(BufferedReader br = new BufferedReader(new FileReader(file))) {
		    privateKey[0] = new BigInteger(br.readLine());
		    privateKey[1] = new BigInteger(br.readLine());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return privateKey;
	}
	
	public static String encrypt(String msg) {
		BigInteger[] key = readPublicKey(PUBLIC);
		return (new BigInteger(msg.getBytes())).modPow(key[0], key[1]).toString();
	}
	
	public static String decrypt(String msg) {
		BigInteger[] key = readPrivateKey(PRIVATE);
		return new String((new BigInteger(msg)).modPow(key[0], key[1]).toByteArray());
	}
	
	public static String decryptCRT(int k, String msg, List<BigInteger> factors) {
		BigInteger[] key = readPrivateKey(PRIVATE);
		BigInteger sum = BigInteger.ONE;
		BigInteger c = new BigInteger(msg);
		ExecutorService executor = Executors.newFixedThreadPool(k);
		List<Future<BigInteger>> elements = new ArrayList<Future<BigInteger>>();
		
        for(int i = 0; i < k; i++) {
        	BigInteger factor = factors.get(i);
    		Callable<BigInteger> crt = new CRT(c.modPow(key[0].remainder(factor.subtract(BigInteger.ONE)), factor), factor, key[1]);
            Future<BigInteger> element = executor.submit(crt);
            elements.add(element);
        }
        
        for(Future<BigInteger> e : elements){
            try {
            	BigInteger element = e.get();
            	sum = sum.add(element);
            } catch (InterruptedException | ExecutionException ex) {
                ex.printStackTrace();
            }
        }
		
		return new String(sum.mod(key[1]).toByteArray());
	}
}