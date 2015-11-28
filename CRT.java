package lista4;

import java.math.BigInteger;
import java.util.concurrent.Callable;

public class CRT implements Callable<BigInteger> {

	private BigInteger ai;
	private BigInteger ni;
	private BigInteger n;
	
	public CRT(BigInteger ai, BigInteger ni, BigInteger n) {
		super();
		this.ai = ai;
		this.ni = ni;
		this.n = n;
	}

	@Override
	public BigInteger call() throws Exception {
		return ai.multiply(n.divide(ni)).multiply(n.divide(ni).modInverse(ni));
	}

}
