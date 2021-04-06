package com.tedd.klaus.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Criptografia síncrona são as criptografias que precisam da mesma chave para descriptografar
 * @author Felipe Oliveira
 */
public class CriptografiaSincronaAESEmModoCBC implements Criptografia {
	
	private SecretKey chaveSecreta;
	
	private IvParameterSpec iv;
	
	private Cipher encryptor;
	
	private Cipher decryptor;
	
	public CriptografiaSincronaAESEmModoCBC(SecretKey chaveSecreta, IvParameterSpec iv) throws InvalidKeyException, InvalidAlgorithmParameterException {
		this.chaveSecreta = chaveSecreta;
		this.iv = iv ;
		
		try {
			encryptor = Cipher.getInstance(getAlgoritmo());
			encryptor.init(Cipher.ENCRYPT_MODE, this.chaveSecreta, this.iv);
			decryptor = Cipher.getInstance(getAlgoritmo());
			decryptor.init(Cipher.DECRYPT_MODE, this.chaveSecreta, this.iv);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
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
		return "AES/CBC/PKCS5Padding";
	}

}
