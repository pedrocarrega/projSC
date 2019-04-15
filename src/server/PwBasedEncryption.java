package server;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PwBasedEncryption {

	private byte[] params;
	private final byte[] salt = { (byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52, 
							(byte) 0x3e, (byte) 0xea, (byte) 0xf2};
	private PBEKeySpec keySpec;
	private SecretKeyFactory kf;
	private SecretKey key;
	
	
	public PwBasedEncryption(String pwManager) throws NoSuchAlgorithmException, InvalidKeySpecException {
		keySpec	=  new	PBEKeySpec(pwManager.toCharArray(), salt, 20);
		kf	= SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
		key = kf.generateSecret(keySpec);
	}
	
	public 
	
	
}
