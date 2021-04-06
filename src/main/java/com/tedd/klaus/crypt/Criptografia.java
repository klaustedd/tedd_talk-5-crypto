package com.tedd.klaus.crypt;

public interface Criptografia {
	
	public byte[] criptografar(byte[] conteudoDescriptografado) throws CriptografiaException;
	
	public byte[] descriptografar(byte[] conteudoCriptografado) throws CriptografiaException;
	
	public String getAlgoritmo();

}
