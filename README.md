project-diceros
===============

Diceros is a sub-project of Rhino project which focus on providing a hardware accelerated JCE provider. Initial effort include:
* AES-NI enabled AES/CTR/NOPADDING encryption/decryption support
* Hardware based true random generator (DRNG)

Diceros is not a full featured JCE provider yet for now, but we will make continuous effort towards that goal. You can download the source code and follow the instruction to build it, we have test the functionality in OpenJDK 7.

#### Quick Start

###### Cipher
The example is for AES/CTR/NOPADDING, you can use AES/CBC/NOPADDING,AES/CBC/PKCS5PADDING or AES/MBCBC/PKCS5PADDING instead of.

```java
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class does the correctness test of AES CTR mode algorithm
 */
public class AESTest {
	public static final int BYTEBUFFER_SIZE = 1000;

	public AESTest() {
	}

	/**
	 * AES Test with byte array as input data, first encrypt the
	 * <code>input</code>, then decrypt the ciphertext result and compare it with
	 * the <code>input</code>.
	 * 
	 * @param keyBytes
	 *          the key data
	 * @param input
	 *          the input data
	 * @throws Exception
	 */
	private void testByteArray(byte[] keyBytes, byte[] input) throws Exception {
		Key key;
		Cipher in, out;
		CipherInputStream cIn;
		CipherOutputStream cOut;
		ByteArrayInputStream bIn;
		ByteArrayOutputStream bOut;

		key = new SecretKeySpec(keyBytes, "AES");

		in = Cipher.getInstance("AES/CTR/NoPadding", "DC");
		out = Cipher.getInstance("AES/CTR/NoPadding", "DC");

		try {
			out.init(Cipher.ENCRYPT_MODE, key);
		} catch (Exception e) {
			System.err.println("AES failed initialisation - " + e.toString());
			return;
		}

		try {
			in.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(
					out.getIV()));
		} catch (Exception e) {
			System.err.println("AES failed initialisation - " + e.toString());
			return;
		}

		// encryption pass
		bOut = new ByteArrayOutputStream();
		cOut = new CipherOutputStream(bOut, out);
		try {
			for (int i = 0; i != input.length / 2; i++) {
				cOut.write(input[i]);
			}
			cOut.write(input, input.length / 2, input.length - input.length / 2);
			cOut.close();
		} catch (IOException e) {
			System.err.println("AES failed encryption - " + e.toString());
			return;
		}

		byte[] bytes = bOut.toByteArray();

		// decryption pass
		bIn = new ByteArrayInputStream(bytes);
		cIn = new CipherInputStream(bIn, in);
		byte[] decBytes = null;
		try {
			DataInputStream dIn = new DataInputStream(cIn);
			decBytes = new byte[input.length];
			for (int i = 0; i != input.length / 2; i++) {
				decBytes[i] = (byte) dIn.read();
			}
			dIn.readFully(decBytes, input.length / 2, decBytes.length - input.length
					/ 2);
		} catch (Exception e) {
			System.err.println("AES failed encryption - " + e.toString());
			return;
		}
		
		for(int i = 0; i < input.length; i++) {
			if (input[i] != decBytes[i]) {
				System.err.println("AES failed decryption.");
				return;
			}
		}
		System.out.println("success");
	}

	/**
	 * AES Test with direct byte buffer as input data, first encrypt the
	 * <code>input</code>, then decrypt the ciphertext result and compare it with
	 * the <code>input</code>.
	 * 
	 * @param keyBytes
	 *          the key data
	 * @param input
	 *          the input data
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws ShortBufferException
	 * @throws Exception
	 * @throws BadPaddingException
	 */
	public void testByteBuffer(byte[] keyBytes, ByteBuffer input)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, ShortBufferException, Exception,
			BadPaddingException {
		ByteBuffer output = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
		ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
		Key key;
		Cipher enc, dec;

		key = new SecretKeySpec(keyBytes, "AES");

		enc = Cipher.getInstance("AES/CTR/NoPadding", "DC");
		dec = Cipher.getInstance("AES/CTR/NoPadding", "DC");

		enc.init(Cipher.ENCRYPT_MODE, key);
		dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(enc.getIV()));

		// encryption pass
		enc.doFinal(input, output);
		output.flip();

		// decryption pass
		dec.doFinal(output, decResult);
		input.flip();
		decResult.flip();

		if (!input.equals(decResult)) {
			byte[] inArray = new byte[input.remaining()];
			byte[] decResultArray = new byte[decResult.remaining()];
			input.get(inArray);
			decResult.get(decResultArray);
			System.err.println("AES failed decryption");
		} else {
			System.out.println("success");
		}
	}

	/**
	 * Perform the aes correctness test.
	 */
	public void performTest() throws Exception {
		byte[] key16 = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(key16); //generate the key data
		String input = "hello world hello world hello world hello world hello world hello world";
		testByteArray(key16, input.getBytes());

		ByteBuffer inputBuffer = ByteBuffer.allocateDirect(input.getBytes().length);
		inputBuffer.put(input.getBytes());
		inputBuffer.flip();
		testByteBuffer(key16, inputBuffer);
	}

	public static void main(String[] args) throws Exception {
		new AESTest().performTest();
	}
}
```
###### DRNG
```java
import java.security.SecureRandom;
import java.security.Security;

public class DRNGTest {
	public static void main(String[] args) {
		SecureRandom random = SecureRandom.getInstance("DRNG", "DC");
		random.nextDouble();
		byte[] bytes = new byte[20];
		random.nextBytes(bytes);
	}
}
```
#### Build 
mvn package -Dmaven.test.skip=true

#### Validate
mvn test  

#### Deploy
* hardware prerequisite:   
Intel® Digital Random Number Generator (DRNG)   
AES-NI

* software prerequisite:   
<p>openssl-1.0.1c or above(just test openssl-1.0.1e);  </p> 
<p>openjdk7;    </p>
<p>add "libdiceros.so"(which is generated after build) to the environment variable "java.library.path"; </p>
<p>add "diceros-1.0.0.jar"(which is generated after build) to the classpath; </p>
<p>if you are using the cipher of "AES/MBCBC/PKCS5PADDING", add "libaesmb.so"(which is the lib of Multi-Buffer) to the environment variable "java.library.path". </p>

* static deploy:   
add line "security.provider.10=com.intel.diceros.provider.DicerosProvider" in file "\<java-home\>\lib\security\java.security"

* dynamic deploy:   
add the following line "Security.addProvider(new com.intel.diceros.provider.DicerosProvider());"    
before calling method "SecureRandom.getInstace()" or "Cipher.getInstance()".
