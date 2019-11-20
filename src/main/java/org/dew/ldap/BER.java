package org.dew.ldap;

import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.logging.Logger;

public 
class BER implements ILDAPConstants
{
  private static Logger oLogger = Logger.getLogger(BER.class.getName());
  
  public static
  LDAPMessage parseMessage(InputStream inputStream)
    throws IOException
  {
    int iMessageId  = 0;
    int iProtocolOp = 0;
    List<Object> listControls = null;
    boolean boBeginSequence = true;
    while(true) {
      int b = inputStream.read();
      if(boBeginSequence) {
        if(b == 0xa0) {
          // Controllo
          int iLenControllo = decodeLength(inputStream);
          for(int i = 0; i < iLenControllo; i++) inputStream.read();
          continue;
        }
        else
        if(b != LBER_SEQUENCE) return null;
        int iTotalLength = decodeLength(inputStream);
        if(iTotalLength <= 0) return null;
        boBeginSequence  = false;
        // Dopo la lunghezza c'� l'intero che rappresenta il MessageId
        inputStream.read(); // LBER_INTEGER
        iMessageId = decodeInteger(inputStream);
      }
      else {
        iProtocolOp  = b;
        int iControlsLength = decodeLength(inputStream);
        listControls = parseListOfValues(inputStream, iControlsLength);
        break;
      }
      if(iProtocolOp > 0) break;
    }
    return new LDAPMessage(iMessageId, iProtocolOp, listControls);
  }
  
  public static
  void sendResult(OutputStream os, int iMessageId, int iResProtocolOp, int iResultCode)
    throws Exception
  {
    if(LDAPServerConfig.LOG_ENABLED) {
      if(iResultCode == LDAP_SUCCESS) {
        oLogger.fine("r: " + iMessageId + ", " + descResProtocolOp(iResProtocolOp) + ", OK...");
      }
      else {
        oLogger.fine("r: " + iMessageId + ", " + descResProtocolOp(iResProtocolOp) + ", Error = " + iResultCode + "...");
      }
    }
    byte[] abMessageId = encodeInteger(iMessageId);
    // BER Sequence
    os.write(LBER_SEQUENCE);
    os.write((byte) 9 + abMessageId.length);
    // Message Id
    os.write(abMessageId);
    // BindResponse
    os.write((byte) iResProtocolOp);
    os.write((byte) 7); // Lenghth
    // Result Code (0 = success, 1 = operationsError, 49 = invalidCredentials)
    os.write(LBER_ENUMERATED);
    os.write(1);
    os.write((byte) iResultCode);
    // MatchedDN
    os.write(LBER_OCTETSTRING);
    os.write((byte) 0);
    // ErrorMessage
    os.write(LBER_OCTETSTRING);
    os.write((byte) 0);
    os.flush();
  }
  
  public static
  void sendResourceContent(OutputStream os, int iMessageId, String sResource)
    throws Exception
  {
    URL urlResource = Thread.currentThread().getContextClassLoader().getResource(sResource);
    if(urlResource == null) {
      throw new Exception("Resource " + sResource + " not found");
    }
    InputStream is = urlResource.openStream();
    int iAvailable = is.available();
    if(LDAPServerConfig.LOG_ENABLED) {
      oLogger.fine("r: " + iMessageId + ", " + sResource + " [" + iAvailable + " bytes]...");
    }
    byte[] abMessageId = encodeInteger(iMessageId);
    // BER Sequence
    os.write(LBER_SEQUENCE);
    encodeLength(os, iAvailable + abMessageId.length);
    // Message Id
    os.write(abMessageId);
    // Copy
    int iByte = 0;
    while((iByte = is.read()) != -1) os.write(iByte);
    os.flush();
  }
  
  public static
  void sendSearchResult(OutputStream os, int iMessageId, String sObjectName)
    throws Exception
  {
    if(LDAPServerConfig.LOG_ENABLED) {
      oLogger.fine("r: " + iMessageId + ", " + sObjectName);
    }
    byte[] abMessageId = encodeInteger(iMessageId);
    int iLengthOfObjectName = sObjectName.length();
    int iLengthOfAttributes = 0;
    int iTotalLength        = 0;
    int iResultLength       = 0;
    iResultLength += iLengthOfObjectName + 1 + getBERLengthOfLength(iLengthOfObjectName);
    iResultLength += iLengthOfAttributes + 1 + getBERLengthOfLength(iLengthOfAttributes);
    iTotalLength  += iResultLength  + abMessageId.length  + 1 + getBERLengthOfLength(iResultLength);
    // BER Sequence
    os.write(LBER_SEQUENCE);
    encodeLength(os, iTotalLength);
    // Message Id
    os.write(abMessageId);
    // BindResponse
    os.write(LDAP_RES_SEARCH_ENTRY);
    encodeLength(os, iResultLength);
    // objectName
    os.write(LBER_OCTETSTRING);
    encodeLength(os, iLengthOfObjectName);
    os.write(sObjectName.getBytes());
    // attributes
    os.write(LBER_SEQUENCE);
    encodeLength(os, iLengthOfAttributes);
    // Flush
    os.flush();
  }
  
  public static
  void sendSearchResult(OutputStream os, int iMessageId, String sObjectName, Map<String,List<String>> mapAttributes)
    throws Exception
  {
    if(LDAPServerConfig.LOG_ENABLED) {
      int iAttributes = mapAttributes != null ? mapAttributes.size() : 0;
      if(iAttributes < 3) {
        oLogger.fine("r: " + iMessageId + ", " + sObjectName + ", " + mapAttributes);
      }
      else {
        oLogger.fine("r: " + iMessageId + ", " + sObjectName + ", " + iAttributes + " attributes");
      }
    }
    if(mapAttributes == null) return;
    byte[] abMessageId = encodeInteger(iMessageId);
    int iLengthOfObjectName = sObjectName.length();
    int iLengthOfAttributes = getLenghtAttributes(mapAttributes);
    int iTotalLength        = 0;
    int iResultLength       = 0;
    iResultLength += iLengthOfObjectName + 1 + getBERLengthOfLength(iLengthOfObjectName);
    iResultLength += iLengthOfAttributes + 1 + getBERLengthOfLength(iLengthOfAttributes);
    iTotalLength  += iResultLength  + abMessageId.length  + 1 + getBERLengthOfLength(iResultLength);
    // BER Sequence
    os.write(LBER_SEQUENCE);
    encodeLength(os, iTotalLength);
    // Message Id
    os.write(abMessageId);
    // BindResponse
    os.write(LDAP_RES_SEARCH_ENTRY);
    encodeLength(os, iResultLength);
    // objectName
    os.write(LBER_OCTETSTRING);
    encodeLength(os, iLengthOfObjectName);
    os.write(sObjectName.getBytes());
    // attributes
    os.write(LBER_SEQUENCE);
    encodeLength(os, iLengthOfAttributes);
    encodeAttributes(os, mapAttributes);
    // Flush
    os.flush();
  }
  
  public static
  List<Object> parseListOfValues(InputStream inputStream, int iTotalLength)
    throws IOException
  {
    List<Object> listResult = new ArrayList<Object>();
    if(iTotalLength < 3) return listResult;
    int b = 0;
    int iLenVal = 0;
    int iBytes  = 0;
    while(true) {
      // Il primo byte rappresenta il tipo...
      int iType = inputStream.read();
      iBytes++;
      // Il secondo byte rappresenta la lunghezza...
      int[] aiLengthAndBytes = decodeLengthAndBytesRead(inputStream);
      iLenVal = aiLengthAndBytes[0];
      iBytes += aiLengthAndBytes[1];
      // Successivamente si recupera il valore
      switch (iType) {
        case LBER_NULL:
          listResult.add(null);
          break;
        case LBER_INTEGER:
        case LBER_ENUMERATED:
          int iValue = 0;
          b = inputStream.read() & 0xFF;
          iBytes++;
          if ((b & 0x80) > 0) iValue = -1; /* integer is negative */
          while (iLenVal-- > 0) {
            iValue = (iValue << 8) | b;
            if (iLenVal > 0) {
              b = inputStream.read();
              iBytes++;
            }
          }
          listResult.add(new Integer(iValue));
          break;
        case LBER_BOOLEAN:
          listResult.add(new Boolean(inputStream.read() != 0));
          iBytes++;
          break;
        case LBER_BITSTRING:
        case LBER_OCTETSTRING:
        case LDAP_AUTH_SIMPLE:
          StringBuffer sb = new StringBuffer();
          for(int i = 0; i < iLenVal; i++) {
            sb.append((char) inputStream.read());
            iBytes++;
          }
          listResult.add(sb.toString());
          break;
        case LBER_SEQUENCE:
        case LBER_SET:
          listResult.add(parseListOfValues(inputStream, iLenVal));
          iBytes += iLenVal;
          break;
        case LDAP_FILTER_PRESENT:
        case LDAP_FILTER_AND:
        case LDAP_FILTER_OR:
        case LDAP_FILTER_NOT:
        case LDAP_FILTER_EQUALITY:
        case LDAP_FILTER_SUBSTRINGS:
        case LDAP_FILTER_GE:
        case LDAP_FILTER_LE:
        case LDAP_FILTER_APPROX:
          listResult.add(parseFilter(inputStream, iLenVal, iType));
          iBytes += iLenVal;
          break;
        default:
          byte[] arrayOfBytes = new byte[iLenVal];
          for(int i = 0; i < iLenVal; i++) {
            arrayOfBytes[i] = (byte) inputStream.read();
            iBytes++;
          }
          listResult.add(arrayOfBytes);
      }
      if(iBytes >= iTotalLength) break;
    }
    return listResult;
  }
  
  public static
  String parseFilter(InputStream inputStream, int iTotalLength, int iStartFilter)
    throws IOException
  {
    StringBuffer sbResult = new StringBuffer();
    if(iTotalLength < 3) return sbResult.toString();
    if(iStartFilter == LDAP_FILTER_PRESENT) {
      sbResult.append("(");
      for(int i = 0; i < iTotalLength; i++) {
        sbResult.append((char) inputStream.read());
      }
      sbResult.append("=*)");
      return sbResult.toString();
    }
    String sOperator = "";
    switch(iStartFilter) {
      case LDAP_FILTER_AND:
        sbResult.append("(&");
        sOperator = "=";
        break;
      case LDAP_FILTER_OR:
        sbResult.append("(|");
        sOperator = "=";
        break;
      case LDAP_FILTER_NOT:
        sbResult.append("(!");
        sOperator = "=";
        break;
      case LDAP_FILTER_EQUALITY:
        sbResult.append("(");
        sOperator = "=";
        break;
      case LDAP_FILTER_SUBSTRINGS:
        sbResult.append("(");
        sOperator = "=";
        break;
      case LDAP_FILTER_GE:
        sbResult.append("(");
        sOperator = ">=";
        break;
      case LDAP_FILTER_LE:
        sbResult.append("(");
        sOperator = "<=";
        break;
      case LDAP_FILTER_APPROX:
        sbResult.append("(");
        sOperator = "~=";
        break;
    }
    int b = 0;
    int iLenVal = 0;
    int iBytes  = 0;
    int iToken  = 0;
    while(true) {
      // Il primo byte rappresenta il tipo...
      int iType = inputStream.read();
      iBytes++;
      // Il secondo byte rappresenta la lunghezza...
      int[] aiLengthAndBytes = decodeLengthAndBytesRead(inputStream);
      iLenVal = aiLengthAndBytes[0];
      iBytes += aiLengthAndBytes[1];
      // Successivamente si recupera il valore
      switch (iType) {
        case LBER_NULL:
          if(iToken > 0) {
            sbResult.append(sOperator);
          }
          sbResult.append("NULL");
          iToken++;
          break;
        case LBER_INTEGER:
        case LBER_ENUMERATED:
          int iValue = 0;
          b = inputStream.read() & 0xFF;
          iBytes++;
          if ((b & 0x80) > 0) iValue = -1; /* integer is negative */
          while (iLenVal-- > 0) {
            iValue = (iValue << 8) | b;
            if (iLenVal > 0) {
              b = inputStream.read();
              iBytes++;
            }
          }
          if(iToken > 0) {
            sbResult.append(sOperator);
          }
          sbResult.append(String.valueOf(iValue));
          iToken++;
          break;
        case LBER_BOOLEAN:
          String sValue = inputStream.read() != 0 ? "1" : "0";
          if(iToken > 0) {
            sbResult.append(sOperator);
          }
          sbResult.append(sValue);
          iBytes++;
          iToken++;
          break;
        case LBER_BITSTRING:
        case LBER_OCTETSTRING:
        case LDAP_AUTH_SIMPLE:
          StringBuffer sb = new StringBuffer();
          for(int i = 0; i < iLenVal; i++) {
            sb.append((char) inputStream.read());
            iBytes++;
          }
          if(iToken > 0) {
            sbResult.append(sOperator + sb.toString());
          }
          else {
            sbResult.append(sb.toString());
          }
          iToken++;
          break;
        case LDAP_FILTER_SUBSTR_SEQ:
          int iTypeSubString = inputStream.read();
          iBytes++;
          String sPrefix = "";
          String sSuffix = "";
          if(iTypeSubString == 128) {
            sSuffix = "*";
          }
          else
          if(iTypeSubString == 129) {
            sPrefix = "*";
            sSuffix = "*";
          }
          else
          if(iTypeSubString == 130) {
            sPrefix = "*";
          }
          int iLengthOfString = inputStream.read();
          iBytes++;
          sb = new StringBuffer();
          for(int i = 0; i < iLengthOfString; i++) {
            sb.append((char) inputStream.read());
            iBytes++;
          }
          if(iToken > 0) {
            sbResult.append(sOperator + sPrefix + sb.toString() + sSuffix);
          }
          else {
            sbResult.append(sb.toString());
          }
          iToken++;
          break;
        case LDAP_FILTER_AND:
        case LDAP_FILTER_OR:
        case LDAP_FILTER_NOT:
        case LDAP_FILTER_EQUALITY:
        case LDAP_FILTER_SUBSTRINGS:
        case LDAP_FILTER_GE:
        case LDAP_FILTER_LE:
        case LDAP_FILTER_PRESENT:
        case LDAP_FILTER_APPROX:
          sbResult.append(parseFilter(inputStream, iLenVal, iType));
          iBytes += iLenVal;
          break;
      }
      if(iBytes >= iTotalLength) break;
    }
    sbResult.append(")");
    return sbResult.toString();
  }
  
  public static
  void encodeAttributes(OutputStream outputStream, Map<String,List<String>> mapAttributes)
    throws Exception
  {
    if(mapAttributes == null || mapAttributes.isEmpty()) return;
    
    Iterator<Map.Entry<String,List<String>>> iterator = mapAttributes.entrySet().iterator();
    while(iterator.hasNext()) {
      Map.Entry<String,List<String>> entry = iterator.next();
      int iLengthOfSubSequence = 0;
      String sKey      = entry.getKey();
      int iLengthOfKey = sKey.length();
      
      iLengthOfSubSequence += iLengthOfKey + 1 + getBERLengthOfLength(iLengthOfKey);
      
      int iLengthOfSet = 0;
      List<String> listValues = entry.getValue();
      for(int j = 0; j < listValues.size(); j++) {
        String sValue  = listValues.get(j);
        int iValLength = sValue.length();
        iLengthOfSet += iValLength + 1 + getBERLengthOfLength(iValLength);
      }
      iLengthOfSubSequence += iLengthOfSet + 1 + getBERLengthOfLength(iLengthOfSet);
      
      outputStream.write(LBER_SEQUENCE);
      encodeLength(outputStream, iLengthOfSubSequence);
      outputStream.write(LBER_OCTETSTRING);
      encodeLength(outputStream, iLengthOfKey);
      outputStream.write(sKey.getBytes());
      outputStream.write(LBER_SET);
      encodeLength(outputStream, iLengthOfSet);
      for(int j = 0; j < listValues.size(); j++) {
        String sValue  = listValues.get(j);
        outputStream.write(LBER_OCTETSTRING);
        encodeLength(outputStream, sValue.length());
        outputStream.write(sValue.getBytes());
      }
    }
  }
  
  public static
  int getLenghtAttributes(Map<String,List<String>> mapAttributes)
  {
    if(mapAttributes == null || mapAttributes.isEmpty()) return 0;
    int iResult = 0;
    Iterator<Map.Entry<String,List<String>>> iterator = mapAttributes.entrySet().iterator();
    while(iterator.hasNext()) {
      Map.Entry<String,List<String>> entry = iterator.next();
      int iLengthOfSubSequence = 0;
      String sKey      = entry.getKey();
      int iLengthOfKey = sKey.length();
      iLengthOfSubSequence += iLengthOfKey + 1 + getBERLengthOfLength(iLengthOfKey);
      int iLengthOfSet = 0;
      List<String> listValues = entry.getValue();
      for(int i = 0; i < listValues.size(); i++) {
        String sValue  = listValues.get(i);
        int iValLength = sValue.length();
        iLengthOfSet += iValLength + 1 + getBERLengthOfLength(iValLength);
      }
      iLengthOfSubSequence += iLengthOfSet + 1 + getBERLengthOfLength(iLengthOfSet);
      iResult += iLengthOfSubSequence + 1 + getBERLengthOfLength(iLengthOfSubSequence);
    }
    return iResult;
  }
  
  public static 
  void encodeLength(OutputStream os, int i)
    throws IOException
  {
    if(i < 0) {
      os.write(-124);
      os.write(i >> 24 & 0xff);
      os.write(i >> 16 & 0xff);
      os.write(i >> 8 & 0xff);
      os.write(i & 0xff);
    } 
    else if(i < 128) {
      os.write(i);
    }
    else if(i <= 255) {
      os.write(-127);
      os.write(i);
    } 
    else if(i <= 65535) {
      os.write(-126);
      os.write(i >> 8 & 0xff);
      os.write(i & 0xff);
    } 
    else if(i <= 0xffffff) {
      os.write(-125);
      os.write(i >> 16 & 0xff);
      os.write(i >> 8 & 0xff);
      os.write(i & 0xff);
    } 
    else {
      os.write(-124);
      os.write(i >> 24 & 0xff);
      os.write(i >> 16 & 0xff);
      os.write(i >> 8 & 0xff);
      os.write(i & 0xff);
    }
  }
  
  public static 
  byte[] encodeInteger(int value)
    throws IOException
  {
    int integer = value;
    int mask;
    int intsize = 4;
    /*
     * Truncate "unnecessary" bytes off of the most significant end of this
     * 2's complement integer.  There should be no sequence of 9
     * consecutive 1's or 0's at the most significant end of the
     * integer.
     */
    mask = 0x1FF << ((8 * 3) - 1);
    /* mask is 0xFF800000 on a big-endian machine */
    while((((integer & mask) == 0) || ((integer & mask) == mask))
        && intsize > 1){
      intsize--;
      integer <<= 8;
    }
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(LBER_INTEGER);
    encodeLength(baos, intsize);
    mask = 0xFF << (8 * 3);
    /* mask is 0xFF000000 on a big-endian machine */
    while ((intsize--) > 0){
      baos.write(((integer & mask) >> (8 * 3)));
      integer <<= 8;
    }
    return baos.toByteArray();
  }
  
  public static 
  int decodeLength(InputStream inputStream)
    throws IOException
  {
    int i = 0;
    int j = inputStream.read();
    if((j & 0xffffff80) > 0) {
      j &= 0x7f;
      if(j == 0) throw new IOException("Indefinite lengths are not supported");
      if(j  > 4) throw new IOException("Data length > 4 bytes are not supported");
      for(int k = 0; k < j; k++) {
        int l = inputStream.read() & 0xff;
        i |= l << 8 * (j - 1 - k);
      }
      if(i < 0) throw new IOException("Does not support data lengths > 2^31");
    } 
    else {
      i = j & 0xff;
    }
    return i;
  }
  
  public static 
  int[] decodeLengthAndBytesRead(InputStream inputStream)
    throws IOException
  {
    int[] aiResult = new int[2];
    int iBytes = 0;
    int i = 0;
    int j = inputStream.read();
    iBytes++;
    if((j & 0xffffff80) > 0) {
      j &= 0x7f;
      if(j == 0) throw new IOException("Indefinite lengths are not supported");
      if(j  > 4) throw new IOException("Data length > 4 bytes are not supported");
      for(int k = 0; k < j; k++) {
        int l = inputStream.read() & 0xff;
        i |= l << 8 * (j - 1 - k);
        iBytes++;
      }
      if(i < 0) throw new IOException("Does not support data lengths > 2^31");
    } 
    else {
      i = j & 0xff;
    }
    aiResult[0] = i;
    aiResult[1] = iBytes;
    return aiResult;
  }
  
  public static 
  int decodeInteger(InputStream is)
    throws IOException
  {
    int length;
    int value = 0;
    length = decodeLength(is);
    if(length > 4) {
      throw new IOException("Length greater than 32bit are not supported for integers.");
    }
    int b = is.read() & 0xFF;
    if ((b & 0x80) > 0) {
      value = -1; /* integer is negative */
    }
    while (length-- > 0) {
      value = (value << 8) | b;
      if (length > 0) {
        b = is.read();
      }
    }
    return value;
  }
  
  public static 
  int getBERLengthOfLength(int i)
  {
    if(i < 0)      return 5;
    if(i < 128)    return 1;
    if(i <= 255)   return 2;
    if(i <= 65535) return 3;
    return i > 0xffffff ? 5 : 4;
  }
  
  public static
  String descResProtocolOp(int iResProtocolOp)
  {
    String sResult = null;
    switch (iResProtocolOp) {
      case ILDAPConstants.LDAP_RES_BIND:          sResult = "res bind";      break;
      case ILDAPConstants.LDAP_RES_SEARCH:        sResult = "res search";    break;
      case ILDAPConstants.LDAP_RES_SEARCH_ENTRY:  sResult = "search entry";  break;
      case ILDAPConstants.LDAP_RES_SEARCH_RESULT: sResult = "search result"; break;
      case ILDAPConstants.LDAP_RES_MODIFY:        sResult = "res modify";    break;
      case ILDAPConstants.LDAP_RES_ADD:           sResult = "res add";       break;
      case ILDAPConstants.LDAP_RES_DELETE:        sResult = "res delete";    break;
      case ILDAPConstants.LDAP_RES_MODRDN:        sResult = "res modrdn";    break;
      case ILDAPConstants.LDAP_RES_COMPARE:       sResult = "res compare";   break;
      default: sResult = String.valueOf(iResProtocolOp); break;
    }
    return sResult;
  }
}
