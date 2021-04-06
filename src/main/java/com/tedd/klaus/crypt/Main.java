package com.tedd.klaus.crypt;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Spliterators;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FileUtils;

import com.google.common.base.Splitter;

public class Main {

	public static void main(String[] args) throws IOException {
		//criptografiaSincrona();
		criptografiaAssincrona();
	}
	
	public static void criptografiaAssincrona() throws IOException {
		long end = 0; 
		long start = 0;
		String mensagem = "Interessante";
		KeyPair keypair = gerarParDeChavesAleatoria(4096);
		//KeyPair keypair = lerParDeChavesDeArquivo();
		System.out.println(keypair.getPrivate().getEncoded().length);
		System.out.println(keypair.getPublic().getEncoded().length);
		
		String publicKeyPEM = toPEM("PUBLIC KEY", keypair.getPublic().getEncoded());
		String privateKeyPEM = toPEM("PRIVATE KEY", keypair.getPrivate().getEncoded());
		
		System.out.println(publicKeyPEM);
		System.out.println(privateKeyPEM);
		
		CriptografiaAssincronaComRSA cipher = new CriptografiaAssincronaComRSA(keypair);
		
		try {
			
			start = System.currentTimeMillis();
			byte[] conteudoCriptografado =  cipher.criptografar(mensagem.getBytes());
			//byte[] conteudoCriptografado = FileUtils.readFileToByteArray(new File("C:/tmp/conteudo-criptografado.dat"));
			end = System.currentTimeMillis();
			System.out.println("Conteúdo criptografado: " + new String(conteudoCriptografado));
			System.out.println("tempo para criptografar: " + (end-start));
			
			byte[] conteudoDescriptografado = cipher.descriptografar(conteudoCriptografado);
			System.out.println("tempo para descriptografar: " + (end-start));
			
			salvarDadosAssincrono(mensagem, conteudoCriptografado, keypair, publicKeyPEM, privateKeyPEM);
		} catch (CriptografiaException e) {
			throw new RuntimeException(e);
		}
		
		
	}
	
	private static String toPEM(String type, byte[] keyBytes) {
		String conteudoChaveEmBase64 = Base64.getEncoder().encodeToString(keyBytes);
		String pem = null; 
		pem =  "-----BEGIN " + type + "-----" + System.lineSeparator();
		for (String linha : Splitter.fixedLength(64).split(conteudoChaveEmBase64)) {
			pem += linha + System.lineSeparator();
		}
		pem += "-----END " + type + "-----";
		
		return pem;
	}
	
	
	
	private static KeyPair gerarParDeChavesAleatoria(int bits) {
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(bits);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException();
		}
		
	}
	
	
	private static KeyPair lerParDeChavesDeArquivo() {
		
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(FileUtils.readFileToByteArray(new File("C:/tmp/private.key"))));
			PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(FileUtils.readFileToByteArray(new File("C:/tmp/public.key"))));
			return new KeyPair(publicKey, privateKey);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static void salvarDadosAssincrono(String mensagem, byte[] conteudoCriptografado, KeyPair keyPair, String publicKeyPEM, String privateKeyPEM) {
		
		try {
			FileUtils.writeByteArrayToFile(new File("C:/tmp/private.key"), keyPair.getPrivate().getEncoded());
			FileUtils.writeByteArrayToFile(new File("C:/tmp/public.key"), keyPair.getPublic().getEncoded());
			FileUtils.writeStringToFile(new File("C:/tmp/private.pem"), privateKeyPEM);
			FileUtils.writeStringToFile(new File("C:/tmp/public.pem"), publicKeyPEM);
			FileUtils.writeByteArrayToFile(new File("C:/tmp/conteudo-criptografado.dat"), conteudoCriptografado);
			FileUtils.writeStringToFile(new File("C:/tmp/conteudo-descriptografado.txt"), mensagem);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
	}
	
	
	
	
	
	
	
	//-------------BEGIN CRIPTOGRAFIA SINCRONA---------------------
	
	
	public static void criptografiaSincrona() {
		String mensagem = "Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!";
		
		//SecretKey secretKey = gerarChaveAleatoria(256);
		//IvParameterSpec iv = gerarIVAleatorio(16);
		
		SecretKey secretKey = lerChaveDeArquivo();
		IvParameterSpec iv = lerIVDeArquivo();
		
		long start = System.currentTimeMillis();
		byte[] conteudoCriptografado = criptografarComCriptografiaSimetricaAESEmModoCBC(mensagem, secretKey, iv);
		long  end = System.currentTimeMillis();
		System.out.println("tempo para criptografar: " + (end-start));
		//byte[] conteudoCriptografado = FileUtils.readFileToByteArray(new File("C:/tmp/conteudo-criptografado.dat"));
		start = System.currentTimeMillis();
		descriptografarComCriptografiaSimetricaAESEmModoCBC(conteudoCriptografado, secretKey, iv);
		end = System.currentTimeMillis();
		System.out.println("tempo para descriptografar: " + (end-start));
	}
	
	public static void salvarDados(String mensagem, byte[] conteudoCriptografado, SecretKey secretKey, IvParameterSpec iv) {
		
		try {
			FileUtils.writeByteArrayToFile(new File("C:/tmp/secret.pk"), secretKey.getEncoded());
			FileUtils.writeByteArrayToFile(new File("C:/tmp/iv.pk"), iv.getIV());
			FileUtils.writeByteArrayToFile(new File("C:/tmp/conteudo-criptografado.dat"), conteudoCriptografado);
			FileUtils.writeStringToFile(new File("C:/tmp/conteudo-descriptografado.txt"), mensagem);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
	}
	
	private static byte[] criptografarComCriptografiaSimetricaAESEmModoCBC(String mensagem, SecretKey secretKey, IvParameterSpec iv) {
		
		try {
			CriptografiaSincronaAESEmModoCBC cipher = new CriptografiaSincronaAESEmModoCBC(secretKey, iv);
			byte[] conteudoCriptografado = cipher.criptografar(mensagem.getBytes());
			System.out.println("Conteúdo criptografado: " + (new String(conteudoCriptografado)));
			salvarDados(mensagem, conteudoCriptografado, secretKey, iv);
			return conteudoCriptografado;
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | CriptografiaException e) {
			throw new RuntimeException(e);
		}
		
	}
	
	private static byte[] descriptografarComCriptografiaSimetricaAESEmModoCBC(byte[] conteudoCriptografado, SecretKey secretKey, IvParameterSpec iv) {
		
		try {
			CriptografiaSincronaAESEmModoCBC cipher = new CriptografiaSincronaAESEmModoCBC(secretKey, iv);
			byte[] conteudoDescriptografado = cipher.descriptografar(conteudoCriptografado);
			System.out.println("Conteúdo descriptografado: " + (new String(conteudoDescriptografado)));
			return conteudoDescriptografado;
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | CriptografiaException e) {
			throw new RuntimeException(e);
		}
		
	}
	
	/**
	 * Gera uma chave secreta randômica
	 * @param n - Tamanho da chave
	 * @return
	 */
	public static SecretKey gerarChaveAleatoria(int bits) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(bits);
			return keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static SecretKey lerChaveDeArquivo() {
		try {
			return new SecretKeySpec(FileUtils.readFileToByteArray(new File("C:/tmp/secret.pk")), "AES");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Gera um IV aleatório
	 * @return
	 */
	public static IvParameterSpec gerarIVAleatorio(int bytes) {
		byte[] iv = new byte[bytes];
		new SecureRandom().nextBytes(iv); //Aplica valores aleatórios no IV
		return new IvParameterSpec(iv);
	}
	
	/**
	 * Lê o IV do arquivo localizado em "C:/tmp/iv.pk"
	 * @return
	 */
	public static IvParameterSpec lerIVDeArquivo() {
		try {
			return new IvParameterSpec(FileUtils.readFileToByteArray(new File("C:/tmp/iv.pk")));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	//-------------END CRIPTOGRAFIA SINCRONA---------------------
}
