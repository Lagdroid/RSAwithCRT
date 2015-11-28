package lista4;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

public class PrimesGenerator implements Callable<BigInteger> {

	private int d;
	private static final int maxIt = 16;
	private static final BigInteger TWO = new BigInteger("2");

	public PrimesGenerator(int d) {
		super();
		this.d = d;
	}

	@Override
	public BigInteger call() throws Exception {
		return generate();
	}

	private BigInteger generate() {
		BigInteger prime;

		do {
			prime = BigInteger.probablePrime(d, new SecureRandom());
		} while (prime.mod(TWO).equals(BigInteger.ZERO) || !testMilRab(prime));

		return prime;
	}

	private boolean testMilRab(BigInteger n) {
		int s = 0;
		
		BigInteger d = n.subtract(BigInteger.ONE);
		while(d.mod(TWO).equals(BigInteger.ZERO)) {
			s++;
			d = d.divide(TWO);
		}
		
		for (int i = 0; i < maxIt; i++) {
			BigInteger a = findBase(TWO, n.subtract(BigInteger.ONE));
			BigInteger x = a.modPow(d, n);
			
			if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) {
				continue;
			}
			
			int r = 1;
			for (; r < s; r++) {
				x = x.modPow(TWO, n);
				if (x.equals(BigInteger.ONE))
					return false;
				if (x.equals(n.subtract(BigInteger.ONE)))
					break;
			}
			if (r == s)
				return false;
		}
		
		return true;
	}

	private static BigInteger findBase(BigInteger min, BigInteger max) {
		BigInteger base;
		
		do {
			base = new BigInteger(max.bitLength(), new SecureRandom());
		} while (base.compareTo(min) < 0 || base.compareTo(max) > 0);
		
		return base;
	}
}
