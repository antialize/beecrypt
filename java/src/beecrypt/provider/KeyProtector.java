package beecrypt.provider;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import beecrypt.beeyond.*;

public class KeyProtector
{
	static final byte PKCS12_ID_CIPHER = 0x1;
	static final byte PKCS12_ID_IV     = 0x2;
	static final byte PKCS12_ID_MAC    = 0x3;

	static byte[] pkcs12DeriveKey(MessageDigest md, int blockSize, int keyLength, byte id, byte[] password, byte[] salt, int iterations)
	{
		int remain;

		md.reset();
		md.update(id);

		// hash a whole number of blocks filled with salt data
		if (salt.length > 0)
		{
			remain = ((salt.length / blockSize) + (salt.length % blockSize)) * blockSize;
			while (remain > 0)
			{
				int tmp = (remain > salt.length) ? salt.length : remain;
				md.update(salt, 0, tmp);
				remain -= tmp;
			}
		}
		// hash a whole number of blocks filled with password data
		if (password.length > 0)
		{
			remain = ((password.length / blockSize) + (password.length % blockSize)) * blockSize;
			while (remain > 0)
			{
				int tmp = (remain > password.length) ? password.length : remain;
				md.update(password, 0, tmp);
				remain -= tmp;
			}
		}

		while (iterations-- > 0)
			md.update(md.digest());

		// compute the final digest
		byte[] digest = md.digest();

		// allocate a key of the requested size
		byte[] key = new byte[keyLength];

		if (keyLength > 0)
		{
			// fill the key with the result
			int offset = 0;
			remain = keyLength;
			while (remain > 0)
			{
				int tmp = (remain > digest.length) ? digest.length : remain;
				System.arraycopy(digest, 0, key, offset, tmp);
				offset += tmp;
				remain -= tmp;
			}
		}

		return key;
	}

	private SecretKeySpec _cipher_key;
	private SecretKeySpec _mac_key;
	private IvParameterSpec _iv;

	public KeyProtector(PBEKey key) throws InvalidKeyException, NoSuchAlgorithmException
	{
		byte[] rawKey = key.getEncoded();
		if (rawKey == null)
			throw new InvalidKeyException("PBEKey must have an encoding");

		byte[] salt = key.getSalt();

		int iter = key.getIterationCount();

		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

		_cipher_key = new SecretKeySpec(pkcs12DeriveKey(sha256, 64, 32, PKCS12_ID_CIPHER, rawKey, salt, iter), "RAW");
		_mac_key = new SecretKeySpec(pkcs12DeriveKey(sha256, 64, 32, PKCS12_ID_MAC, rawKey, salt, iter), "RAW");
		_iv = new IvParameterSpec(pkcs12DeriveKey(sha256, 64, 16, PKCS12_ID_IV, rawKey, salt, iter));
	}

	byte[] protect(PrivateKey key)
	{
		if (key.getEncoded() == null)
			return null;
		if (key.getFormat() == null)
			return null;

		try
		{
			byte[] enc = key.getEncoded();

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(bos);

			dos.writeUTF(key.getAlgorithm());
			dos.writeUTF(key.getFormat());
			dos.writeInt(enc.length);
			dos.write(enc);
			dos.close();

			byte[] clearText = bos.toByteArray();

			Mac m = Mac.getInstance("HMAC-SHA-256");

			m.init(_mac_key);

			byte[] mac = m.doFinal(clearText);

			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");

			c.init(Cipher.ENCRYPT_MODE, _cipher_key, _iv);

			return c.doFinal(clearText);
		}
		catch (Exception e)
		{
			return null;
		}
	}

	PrivateKey recover(byte[] encryptedKey) throws NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException
	{
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		Mac m = Mac.getInstance("HMAC-SHA-256");

		final int macLength = m.getMacLength();

		final int cipherTextLength = encryptedKey.length - macLength;
		if (cipherTextLength <= 0)
			throw new UnrecoverableKeyException("encrypted data way too short");

		try
		{
			c.init(Cipher.DECRYPT_MODE, _cipher_key, _iv);

			byte[] clearText = c.doFinal(encryptedKey, 0, cipherTextLength);

			m.init(_mac_key);

			byte[] computedMac = m.doFinal(clearText);

			byte[] originalMac = new byte[m.getMacLength()];

			System.arraycopy(encryptedKey, cipherTextLength, originalMac, 0, macLength);

			if (!Arrays.equals(computedMac, originalMac))
				throw new UnrecoverableKeyException("mac of decrypted key didn't match");

			ByteArrayInputStream bis = new ByteArrayInputStream(clearText);
			DataInputStream dis = new DataInputStream(bis);

			String algorithm = dis.readUTF();
			String format = dis.readUTF();

			int encSize = dis.readInt();
			if (encSize <= 0)
				throw new IOException("key size < 0");

			byte[] enc = new byte[encSize];

			dis.readFully(enc);

			KeyFactory kf = KeyFactory.getInstance(algorithm);

			return kf.generatePrivate(new AnyEncodedKeySpec(format, enc));
		}
		catch (Exception e)
		{
		}
		throw new UnrecoverableKeyException("unable to recover key");
	}
}
