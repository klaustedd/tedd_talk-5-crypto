package com.tedd.klaus.crypt;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CriptografiaAssincronaComRSA implements Criptografia {
	
	private KeyPair keyPair;
	
	private Cipher encryptor;
	
	private Cipher decryptor;
	
	public CriptografiaAssincronaComRSA(KeyPair keyPair) {
		this.keyPair = keyPair;
		
		try {
			encryptor = Cipher.getInstance(getAlgoritmo());
			encryptor.init(Cipher.ENCRYPT_MODE, this.keyPair.getPublic());
			
			decryptor = Cipher.getInstance(getAlgoritmo());
			decryptor.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] criptografar(byte[] conteudoDescriptografado) throws CriptografiaException {
		byte[] conteudoCriptografado;
		try {
			conteudoCriptografado = encryptor.doFinal(conteudoDescriptografado);
			return conteudoCriptografado;
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new CriptografiaException(e);
		}
	}

	public byte[] descriptografar(byte[] conteudoCriptografado) throws CriptografiaException {
		byte[] conteudoDescriptografado;
		try {
			conteudoDescriptografado = decryptor.doFinal(conteudoCriptografado);
			return conteudoDescriptografado;
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new CriptografiaException(e);
		}
	}

	@Override
	public String getAlgoritmo() {
		return "RSA/ECB/PKCS1Padding";
	}

}
