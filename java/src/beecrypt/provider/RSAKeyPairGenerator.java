package beecrypt.provider;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

import beecrypt.security.*;

public final class RSAKeyPairGenerator extends KeyPairGeneratorSpi
{
	private int _size = 1024;
	private SecureRandom _srng;
	private BigInteger _n = null;
	private BigInteger _e = RSAKeyGenParameterSpec.F4;
	private BigInteger _d = null;
	private BigInteger _p = null;
	private BigInteger _q = null;
	private BigInteger _dp = null;
	private BigInteger _dq = null;
	private BigInteger _qi = null;

	private native void generate();

	public KeyPair generateKeyPair()
	{
		generate();

		return new KeyPair(new RSAPublicKeyImpl(_n, _e), new RSAPrivateCrtKeyImpl(_n, _e, _d, _p, _q, _dp, _dq, _qi));
	}

	public void initialize(int keysize, SecureRandom random)
	{
		_size = keysize;
		_e = RSAKeyGenParameterSpec.F4;
		_srng = random;
	}

	public void initialize(AlgorithmParameterSpec spec, SecureRandom random) throws InvalidAlgorithmParameterException
	{
		if (spec instanceof RSAKeyGenParameterSpec)
		{
			RSAKeyGenParameterSpec rs = (RSAKeyGenParameterSpec) spec;

			_size = rs.getKeysize();
			_e = rs.getPublicExponent();
			_srng = random;
		}
		else
			throw new InvalidAlgorithmParameterException("not an RSAKeyGenParameterSpec");
	}
}
