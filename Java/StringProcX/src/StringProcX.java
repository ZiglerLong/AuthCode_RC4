
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.io.UnsupportedEncodingException;

public class StringProcX {
	
	private static String enc_key = "#*Merg^QaNy";
	private static int expiry = 0;
	
	public static enum procMode {
		Encode, Decode
	};
	
	private static char[] base64EncodeChars = new char[]{
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '+', '/'};

    private static byte[] base64DecodeChars = new byte[]{
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};
    
    private static String base64_encode(byte[] data) {
        StringBuffer sb = new StringBuffer();
        int len = data.length;
        int i = 0;
        int b1, b2, b3;
        while (i < len) {
            b1 = data[i++] & 0xff;
            if (i == len) {
                sb.append(base64EncodeChars[b1 >>> 2]);
                sb.append(base64EncodeChars[(b1 & 0x3) << 4]);
                sb.append("==");
                break;
            }
            b2 = data[i++] & 0xff;
            if (i == len) {
                sb.append(base64EncodeChars[b1 >>> 2]);
                sb.append(base64EncodeChars[((b1 & 0x03) << 4) | ((b2 & 0xf0) >>> 4)]);
                sb.append(base64EncodeChars[(b2 & 0x0f) << 2]);
                sb.append("=");
                break;
            }
            b3 = data[i++] & 0xff;
            sb.append(base64EncodeChars[b1 >>> 2]);
            sb.append(base64EncodeChars[((b1 & 0x03) << 4) | ((b2 & 0xf0) >>> 4)]);
            sb.append(base64EncodeChars[((b2 & 0x0f) << 2) | ((b3 & 0xc0) >>> 6)]);
            sb.append(base64EncodeChars[b3 & 0x3f]);
        }
        return sb.toString();
    }
    
    private static byte[] base64_decode(String str) throws UnsupportedEncodingException {
    	int remainder = str.length()%4;
    	if(remainder == 2){
    		str = str + "==";
    	}else if(remainder == 3){
    		str = str + "=";
    	}
        StringBuffer sb = new StringBuffer();
        byte[] data = str.getBytes("US-ASCII");
        int len = data.length;
        int i = 0;
        int b1, b2, b3, b4;
        while (i < len) {
            do {
                b1 = base64DecodeChars[data[i++]];
            } while (i < len && b1 == -1);
            if (b1 == -1) 
            	break;
            do {
                b2 = base64DecodeChars[data[i++]];
            } while (i < len && b2 == -1);
            if (b2 == -1) 
            	break;
            sb.append((char) ((b1 << 2) | ((b2 & 0x30) >>> 4)));
            do {
                b3 = data[i++];
                if (b3 == 61) return sb.toString().getBytes("iso8859-1");
                b3 = base64DecodeChars[b3];
            } while (i < len && b3 == -1);
            if (b3 == -1) 
            	break;
            sb.append((char) (((b2 & 0x0f) << 4) | ((b3 & 0x3c) >>> 2)));
            do {
                b4 = data[i++];
                if (b4 == 61) 
                	return sb.toString().getBytes("iso8859-1");
                b4 = base64DecodeChars[b4];
            } while (i < len && b4 == -1);
            if (b4 == -1) 
            	break;
            sb.append((char) (((b3 & 0x03) << 6) | b4));
        }
        return sb.toString().getBytes("iso8859-1");
    }
    
    private static String cutString(String str, int startIndex, int length) {
		if (startIndex >= 0) {
			if (length < 0) {
				length = length * -1;
				if (startIndex - length < 0) {
					length = startIndex;
					startIndex = 0;
				} else {
					startIndex = startIndex - length;
				}
			}
			if (startIndex > str.length()) {
				return "";
			}
		} else {
			if (length < 0) {
				return "";
			} else {
				if (length + startIndex > 0) {
					length = length + startIndex;
					startIndex = 0;
				} else {
					return "";
				}
			}
		}
		if (str.length() - startIndex < length) {
			length = str.length() - startIndex;
		}
		return str.substring(startIndex, startIndex + length);
	}

	private static String cutString(String str, int startIndex) {
		return cutString(str, startIndex, str.length());
	}
	
	private static String getTimeStamp(){
		return String.format("%010d",System.currentTimeMillis()/1000);
	}
	
	private static String md5_Hash(String md5_String) {
		StringBuffer sb = new StringBuffer();
		String part = null;
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5 = md.digest(md5_String.getBytes());
			for (int i = 0; i < md5.length; i++) {
				part = Integer.toHexString(md5[i] & 0xFF);
				if (part.length() == 1) {
					part = "0" + part;
				}
				sb.append(part);
			}
		} catch (NoSuchAlgorithmException ex) {
		}
		return sb.toString();
	}
	
	private static short[] byteToShort(byte[] src){
		short[] ret = new short[src.length];
		for(int i=0; i<src.length; i++){
			ret[i] = src[i]>0 ? (short)src[i] : (short)((short)255 - (short)(~src[i]));
		}
		return ret;
	}
	
	private static byte[] listToByte(List<Integer> src){
		byte[] ret = new byte[src.size()];
		for(int i=0; i<src.size(); i++){
			ret[i] = (byte)(int)src.get(i);
		}
		return ret;
	}
	
	public static String procX(String string, procMode operation) throws UnsupportedEncodingException{
		int ckey_length = 4;
	    String key = md5_Hash(md5_Hash(enc_key)); //两轮MD5，防止无聊人士通过彩虹表穷举...
	    String keya = md5_Hash(cutString(key, 0, 16));
	    String keyb = md5_Hash(cutString(key, 16, 16));
	    string = string.replace("[a]", "+");
	    string = string.replace("[d]", "/");
	    string = string.replace("[s]", "=");
	    
	    String tt = md5_Hash(getTimeStamp());
	    String keyc = ckey_length > 0 ? (operation == procMode.Decode ? cutString(string, 0, ckey_length): cutString(tt, tt.length()-ckey_length)) : "";
	    //String keyc = ckey_length > 0 ? (operation == procMode.Decode ? cutString(string, 0, ckey_length): "long" ) : "";
	    
	    String cryptkey = keya + md5_Hash(keya + keyc);
	    int key_length = cryptkey.length();
	    
	    List<Integer> array = new ArrayList<Integer>();
	    int string_length = 0;
	    List<Integer> result = new ArrayList<Integer>();
	    
	    if(operation == procMode.Decode){
	    	byte[] btArray = base64_decode(cutString(string, ckey_length));
	    	short[] normal = byteToShort(btArray);
	    	string_length = normal.length;
	    	for(int i=0; i<normal.length; i++){
	    		array.add((int) normal[i]);
	    	}
	    }else{
	    	String verify = string + keyb;
	    	long ts = Integer.parseInt(getTimeStamp(),10);
	    	String tmp = String.format("%010d%s%s", expiry>0 ? ts+expiry : 0, cutString(md5_Hash(verify), 0, 16), string);
	    	short[] normal = byteToShort(tmp.getBytes("UTF-8"));
	    	string_length = normal.length;
	    	for(int j=0; j<normal.length; j++){
	    		array.add((int) normal[j]);
	    	}
	    }
	    int[] box = new int[256];
	    int[] rndkey = new int[256];
	    for(int i = 0; i <= 255; i++) {
	    	box[i] = i;
	        int pos = i % key_length;
	        byte p = (byte)cryptkey.substring(pos, pos+1).getBytes()[0];
	        int tmp = p >= 0 ? (int)p : (int)(255 - (int)(~p));
	        rndkey[i] = tmp;
	    }
	    int j=0;
	    for(int i=0; i<256; i++){
	    	j = (j + box[i] + rndkey[i]) % 256;
	    	int tmp = box[i];
	    	box[i] = box[j];
	    	box[j] = tmp;
	    }
	    int a = j = 0;
	    for(int i=0; i<string_length; i++){
	    	a = (a + 1) % 256;
	    	j = (j + box[a]) % 256;
	    	int tmp = box[a];
	    	box[a] = box[j];
	    	box[j] = tmp;
	    	int kx = array.get(i) ^ box[(box[a] + box[j]) %256];
	    	result.add(kx);
	    }
	    
	    if(operation == procMode.Decode) {
	    	//把result转为字符串
	    	byte[] ret = new byte[result.size()];
	    	for(int i=0; i<result.size(); i++){
	    		ret[i] = (byte)(int)result.get(i);
	    	}
	    	byte[] toDecode = listToByte(result);
	    	String strDecode = new String(toDecode);
	    	//校验解密结果，符合要求则输出
	    	try {
	    		long ts = Integer.parseInt(cutString(strDecode, 0, 10),10);
		    	long now = Integer.parseInt(getTimeStamp(),10);
		    	String verify = cutString(strDecode, 10, 16);
		    	String hash = cutString(md5_Hash(cutString(strDecode, 26) + keyb), 0, 16);
		    	if((ts==0 || ts-now>0) && (verify.equals(hash))){
		    		return cutString(strDecode, 26);
		    	}else{
		    		return "";
		    	}
			} catch (Exception e) {
				return "";
			}
	    } else {
	    	//把result转为byte[]，进行 BASE64 编码
	    	byte[] toEncode = listToByte(result);
	        String ret = base64_encode(toEncode);
	    	//替换掉可能导致问题的字符
	        ret = ret.replace("+", "[a]");
	        ret = ret.replace("/", "[d]");
	        ret = ret.replace("=", "[s]");
	        return keyc + ret;
	    }
	}
	
	public static void main(String[] args) {
		try {
			String strOrigin = "hello world，我操";
			String enStr = StringProcX.procX(strOrigin, procMode.Encode);
			System.out.println("Before:" + strOrigin);
			String deStr = StringProcX.procX(enStr, procMode.Decode);
			System.out.println("AfterX:" + enStr);
			System.out.println("Decode:" + deStr);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
