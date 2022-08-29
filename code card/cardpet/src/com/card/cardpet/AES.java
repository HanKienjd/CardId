package com.card.cardpet;

import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.AESKey;

public class AES {
	private final javacardx.crypto.Cipher cipher;
	private final byte[] temp;
	
	public AES(){
		cipher=javacardx.crypto.Cipher.getInstance(javacardx.crypto.Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		temp=JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
	}
	public void encrypt(byte[]input,short offset, short length,AESKey key,byte[]output){
		if(length <(short)1){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		byte residual =(byte)(length%16);
		cipher.init(key,javacardx.crypto.Cipher.MODE_ENCRYPT);
		if(residual==(byte)0x00){
			cipher.doFinal(input,offset,length,output,(short)0);
			return;
		}
		cipher.update(input,offset,length,output,(short)0);
		cipher.doFinal(temp,(short)0,(short)(16-residual),output,(short)0);
	}
	
	public short decrypt(byte[]input, short inOffset,short inLength,AESKey key,byte[]output,short outOffset){
		if((short)(inLength%16)!=0){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		cipher.init(key,javacardx.crypto.Cipher.MODE_DECRYPT);
		cipher.doFinal(input, inOffset, inLength, output, outOffset);
		short length;
		for(length=(short)(output.length-1);length>=0;length--){
			if(output[length]!=(byte)0x00){
				break;
			}
		}
		return (short)(length-outOffset+1);
	}
}
