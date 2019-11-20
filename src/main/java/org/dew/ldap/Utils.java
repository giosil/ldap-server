package org.dew.ldap;

import java.security.MessageDigest;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public 
class Utils 
{
	public static
	void normalizeAttributes(List<Object> listAttributes)
	{
		if(listAttributes == null) return;
		int iSize = listAttributes.size();
		if(iSize == 1) {
			Object oItem0 = listAttributes.get(0);
			if(oItem0.equals("*")) {
				listAttributes.clear();
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	public static
	Map<String,Object> getAttributesToModify(List<Object> listAttributesToModify, int iTheOperation)
	{
		Map<String,Object> mapResult = new HashMap<String,Object>();
		if(listAttributesToModify == null || listAttributesToModify.size() == 0) return mapResult;
		for(int i = 0; i < listAttributesToModify.size(); i++) {
			Object oItem = listAttributesToModify.get(i);
			if(oItem instanceof List) {
				List<Object> listItem = (List<Object>) oItem;
				if(listItem.size() < 2) continue;
				Object oOperation = listItem.get(0);
				int iOperation = -1;
				if(oOperation instanceof Number) {
					iOperation = ((Number) oOperation).intValue();
				}
				else 
				if(oOperation instanceof String) {
					try{ iOperation = Integer.parseInt((String) oOperation); }
					catch(Exception ex) {}
				}
				if(iOperation == iTheOperation) {
					Object oAttributeNameAndValues = listItem.get(1);
					if(oAttributeNameAndValues instanceof List) {
						List<Object> listAttributeNameAndValues = (List<Object>) oAttributeNameAndValues;
						if(listAttributeNameAndValues.size() < 2) continue;
						Object oAttributeName = listAttributeNameAndValues.get(0);
						if(oAttributeName != null) {
							Object oValues = listAttributeNameAndValues.get(1);
							if(oValues instanceof List) {
								List<Object> listValues = (List<Object>) oValues;
								if(listValues.size() == 1) {
									mapResult.put(oAttributeName.toString(), listValues.get(0));
								}
								else
								if(listValues.size() > 1) {
									mapResult.put(oAttributeName.toString(), listValues);
								}
							} // end if(oValues instanceof List)
						} // end if(oAttributeName != null)
					} // end if(oAttributeNameAndValues instanceof List
				} // end if(iOperation == iTheOperation)
			} // if(oItem instanceof List) 
		}
		return mapResult;
	}
	
	public static
	boolean isNoAttributes(List<Object> listAttributes)
	{
		if(listAttributes != null && listAttributes.size() == 1) {
			String sFirstAttribute = (String) listAttributes.get(0);
			if("1.1".equals(sFirstAttribute)) return true;
			if(sFirstAttribute != null && sFirstAttribute.equalsIgnoreCase("objectclass")) {
				return true;
			}
		}
		if(listAttributes != null && listAttributes.size() == 2) {
			String sFirstAttribute  = (String) listAttributes.get(0);
			String sSecondAttribute = (String) listAttributes.get(1);
			if(sFirstAttribute != null && sFirstAttribute.equalsIgnoreCase("hasSubordinates")) {
				if("1.1".equals(sSecondAttribute)) return true;
				if(sSecondAttribute != null && sSecondAttribute.equalsIgnoreCase("objectclass")) {
					return true;
				}
			}
			if(sSecondAttribute != null && sSecondAttribute.equalsIgnoreCase("hasSubordinates")) {
				if("1.1".equals(sFirstAttribute)) return true;
				if(sFirstAttribute != null && sFirstAttribute.equalsIgnoreCase("objectclass")) {
					return true;
				}
			}
		}
		return false;
	}
	
	public static
	boolean findPerson(String sFilter)
	{
		if(sFilter == null || sFilter.length() == 0) return false;
		if(sFilter.equalsIgnoreCase("(objectClass=inetOrgPerson)")) {
			return true;
		}
		else
		if(sFilter.equalsIgnoreCase("(objectClass=organizationalPerson)")) {
			return true;
		}
		else
		if(sFilter.equalsIgnoreCase("(objectClass=person)")) {
			return true;
		}
		return false;
	}
	
	public static
	boolean findGroupOfUniqueNames(String sFilter)
	{
		if(sFilter == null || sFilter.length() == 0) return false;
		String sFilterLC = sFilter.toLowerCase();
		if(sFilterLC.indexOf("objectclass=groupofuniquenames") >= 0) {
			return true;
		}
		return false;
	}
	
	public static
	String getFilterCategory(String sFilter)
	{
		if(sFilter == null || sFilter.length() == 0) return "";
		int begin = sFilter.indexOf("(objectCategory=");
		if(begin < 0) return "";
		int end = sFilter.indexOf(')', begin + 1);
		if(end < 0) return "";
		return sFilter.substring(begin + 16, end);
	}
	
	public static
	String getFilterValue(String sFilter, String sField)
	{
		if(sFilter == null || sFilter.length() == 0) return "";
		int begin = sFilter.indexOf("(" + sField + "=");
		if(begin < 0) return "";
		int end = sFilter.indexOf(')', begin + 1);
		if(end < 0) return "";
		return sFilter.substring(begin + sField.length() + 2, end);
	}
	
	public static
	String getUniqueMemberUid(String sFilter)
	{
		String sUniqueMember = "uniquemember=uid=";
		String sFilterLC = sFilter.toLowerCase();
		int iStartUid = sFilterLC.indexOf(sUniqueMember);
		if(iStartUid >= 0) {
			iStartUid   = iStartUid + sUniqueMember.length();
			int iEndUid = sFilter.indexOf(',', iStartUid);
			String sUid = iEndUid > 0 ? sFilter.substring(iStartUid, iEndUid) : sFilter.substring(iStartUid);
			return sUid;
		}
		return null;
	}
	
	public static
	String getMemberUid(String sFilter)
	{
		String sMember = "member=uid=";
		String sFilterLC = sFilter.toLowerCase();
		int iStartUid = sFilterLC.indexOf(sMember);
		if(iStartUid >= 0) {
			iStartUid   = iStartUid + sMember.length();
			int iEndUid = sFilter.indexOf(',', iStartUid);
			String sUid = iEndUid > 0 ? sFilter.substring(iStartUid, iEndUid) : sFilter.substring(iStartUid);
			return sUid;
		}
		return null;
	}
	
	public static
	String getDistinguishedNameUid(String sFilter)
	{
		String sDN = "distinguishedname=uid=";
		String sFilterLC = sFilter.toLowerCase();
		int iStartUid = sFilterLC.indexOf(sDN);
		if(iStartUid >= 0) {
			iStartUid   = iStartUid + sDN.length();
			int iEndUid = sFilter.indexOf(',', iStartUid);
			String sUid = iEndUid > 0 ? sFilter.substring(iStartUid, iEndUid) : sFilter.substring(iStartUid);
			return sUid;
		}
		return null;
	}
	
	public static
	String getUserPrincipalName(String sFilter)
	{
		String sUserPrin = "userprincipalname=";
		String sFilterLC = sFilter.toLowerCase();
		int iStartUid = sFilterLC.indexOf(sUserPrin);
		if(iStartUid >= 0) {
			iStartUid   = iStartUid + sUserPrin.length();
			int iEndUid = sFilter.indexOf(')', iStartUid);
			String sUid = iEndUid > 0 ? sFilter.substring(iStartUid, iEndUid) : sFilter.substring(iStartUid);
			return sUid;
		}
		return null;
	}
	
	public static
	int getResProtocolOp(int iProtocolOp)
	{
		switch (iProtocolOp) {
			case ILDAPConstants.LDAP_REQ_BIND:
				return ILDAPConstants.LDAP_RES_BIND;
			case ILDAPConstants.LDAP_REQ_SEARCH:
				return ILDAPConstants.LDAP_RES_SEARCH;
			case ILDAPConstants.LDAP_REQ_MODIFY:  
				return ILDAPConstants.LDAP_RES_MODIFY;
			case ILDAPConstants.LDAP_REQ_ADD:
				return ILDAPConstants.LDAP_RES_ADD;
			case ILDAPConstants.LDAP_REQ_DELETE:
				return ILDAPConstants.LDAP_RES_DELETE;
			case ILDAPConstants.LDAP_REQ_MODRDN:
				return ILDAPConstants.LDAP_RES_MODRDN;
			case ILDAPConstants.LDAP_REQ_COMPARE:
				return ILDAPConstants.LDAP_RES_COMPARE;
		}
		return ILDAPConstants.LDAP_RES_SEARCH;
	}
	
	public static
	void put(Map<String,List<String>> mapAttributes, String sKey, Object... aoValues)
	{
		if(aoValues == null) return;
		List<String> listOfValues = new ArrayList<String>(1);
		for(Object oValue : aoValues) {
			if(oValue != null) {
				if(oValue instanceof Date) {
					listOfValues.add(String.valueOf(dateToInt((Date) oValue)));
				}
				else
				if(oValue instanceof Calendar) {
					listOfValues.add(String.valueOf(calendarToInt((Calendar) oValue)));
				}
				else {
					listOfValues.add(oValue.toString());
				}
			}
		}
		mapAttributes.put(sKey, listOfValues);
	}
	
	public static
	void checkPut(List<Object> listAttributesToCheck, Map<String,List<String>> mapAttributes, String sKey, Object... aoValues)
	{
		if(aoValues == null) return;
		if(listAttributesToCheck != null && listAttributesToCheck.size() > 0 && !listAttributesToCheck.contains(sKey)) return;
		List<String> listOfValues = new ArrayList<String>(1);
		for(Object oValue : aoValues) {
			if(oValue != null) {
				if(oValue instanceof Date) {
					listOfValues.add(String.valueOf(dateToInt((Date) oValue)));
				}
				else
				if(oValue instanceof Calendar) {
					listOfValues.add(String.valueOf(calendarToInt((Calendar) oValue)));
				}
				else {
					listOfValues.add(oValue.toString());
				}
			}
		}
		mapAttributes.put(sKey, listOfValues);
	}
	
	public static
	void put(Map<String,List<String>> mapAttributes, String sKey, List<String> listOfValues)
	{
		if(listOfValues == null) return;
		mapAttributes.put(sKey, listOfValues);
	}
	
	public static
	Map<String,List<String>> buildAttributes(String sKeyValue, Map<String,List<String>> map)
	{
		Map<String,List<String>> mapResult = new HashMap<String,List<String>>(map);
		if(sKeyValue != null && sKeyValue.length() >= 0) {
			int iSep = sKeyValue.indexOf('=');
			String sKey = null;
			String sValue = null;
			if(iSep > 0) {
				sKey = sKeyValue.substring(0, iSep);
				sValue = sKeyValue.substring(iSep + 1);
			}
			else {
				sKey = "ou";
				sValue = sKeyValue;
			}
			put(mapResult, sKey, sValue);
		}
		return mapResult;
	}
	
	public static 
	String getFirstName(String sBaseObject) {
		int iStart = sBaseObject.indexOf("=");
		if(iStart < 0) return sBaseObject;
		int iSep = sBaseObject.indexOf(',', iStart);
		if(iSep > 0) {
			return sBaseObject.substring(iStart + 1, iSep).trim();
		}
		return sBaseObject.substring(iStart + 1).trim();
	}
	
	public static
	String getDigestMD5(String sText)
	  throws Exception
	{
		if(sText == null) sText = "";
		String sResult = null;
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(sText.getBytes());
			sResult = "{MD5}" + String.valueOf(Base64Coder.encode(md.digest()));
		}
		catch(Exception ex) {
			sResult = sText;
		}
		return sResult;
	}
	
	public static
	String getDigestSHA(String sText)
	{
		if(sText == null) sText = "";
		String sResult = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(sText.getBytes());
			sResult = "{SHA}" + String.valueOf(Base64Coder.encode(md.digest()));
		}
		catch(Exception ex) {
			sResult = sText;
		}
		return sResult;
	}
	
	public static 
	String normalizeDate(String sDate) {
		if(sDate == null || sDate.length() == 0) return "NULL";
		StringBuffer sbResult = new StringBuffer();
		int iFirstNotDigit = -1;
		for(int i = 0; i < sDate.length(); i++) {
			char c = sDate.charAt(i);
			if(Character.isDigit(c)) {
				sbResult.append(c);
			}
			else {
				if(iFirstNotDigit < 0) iFirstNotDigit = i;
			}
		}
		String sResult = sbResult.toString();
		if(iFirstNotDigit > 3) {
			// Anno Mese Giorno
			return sResult;
		}
		else
		if(iFirstNotDigit > 1) {
			// Giorno Mese Anno
			if(sResult.length() > 4) {
				return sResult.substring(4) + sResult.substring(2, 4) + sResult.substring(0, 2); 
			}
			else {
				return sResult;
			}
		}
		return sResult;
	}
	
	public static 
	String normalizeInteger(String sNumber) {
		if(sNumber == null || sNumber.length() == 0) return "NULL";
		StringBuffer sbResult = new StringBuffer();
		for(int i = 0; i < sNumber.length(); i++) {
			char c = sNumber.charAt(i);
			if(Character.isDigit(c)) {
				sbResult.append(c);
			}
		}
		return sbResult.toString();
	}
	
	public static
	int dateToInt(Date oDate)
	{
		if(oDate == null) return 0;
		Calendar cal = Calendar.getInstance();
		cal.setTime(oDate);
		return cal.get(Calendar.YEAR) * 10000 + (cal.get(Calendar.MONTH) + 1) * 100 + cal.get(Calendar.DAY_OF_MONTH);
	}
	
	public static
	int calendarToInt(Calendar cal)
	{
		if(cal == null) return 0;
		return cal.get(Calendar.YEAR) * 10000 + (cal.get(Calendar.MONTH) + 1) * 100 + cal.get(Calendar.DAY_OF_MONTH);
	}
	
	public static
	int timeToInt(Date oDate)
	{
		if(oDate == null) return 0;
		Calendar cal = Calendar.getInstance();
		cal.setTime(oDate);
		return cal.get(Calendar.HOUR_OF_DAY) * 100 + cal.get(Calendar.MINUTE);
	}
	
	public static
	String dateTimeToTimeStamp(Date oDate)
	{
		if(oDate == null) return "";
		Calendar cal = Calendar.getInstance();
		cal.setTime(oDate);
		int iDate = cal.get(Calendar.YEAR) * 10000 + (cal.get(Calendar.MONTH) + 1) * 100 + cal.get(Calendar.DAY_OF_MONTH);
		int iTime = cal.get(Calendar.HOUR_OF_DAY) * 10000 + cal.get(Calendar.MINUTE) * 100 + cal.get(Calendar.SECOND);
		return String.valueOf(iDate) + lpad(String.valueOf(iTime), '0', 6) + "Z";
	}
	
	public static
	String lpad(String text, char c, int length)
	{
		if(text == null) text = "";
		int iTextLength = text.length();
		if(iTextLength >= length) return text;
		int diff = length - iTextLength;
		StringBuffer sb = new StringBuffer();
		for(int i = 0; i < diff; i++) sb.append(c);
		sb.append(text);
		return sb.toString();
	}
	
	public static
	String buildClause(Map<String,String> mapFields, String sFilter, boolean boNot)
	{
		int iSep = sFilter.indexOf('=');
		if(iSep < 0) return "";
		String sKey    = sFilter.substring(0, iSep);
		String sValue  = sFilter.substring(iSep + 1);
		boolean boLike = sValue.indexOf('*') >= 0;
		
		String sField = mapFields.get(sKey);
		if(sField == null || sField.length() == 0) {
			if(sKey.equalsIgnoreCase("cn") || sKey.equalsIgnoreCase("displayName")) {
				int iSepValues = sValue.indexOf('-');
				if(iSepValues < 0) iSepValues = sValue.indexOf(' ');
				if(iSepValues < 0) iSepValues = sValue.indexOf(',');
				String sValue1 = iSepValues <= 0 ? sValue : sValue.substring(0, iSepValues);
				String sValue2 = iSepValues <= 0 ? null : sValue.substring(iSepValues + 1);
				String sResult = buildClause(mapFields, "givenName=" + sValue1.toUpperCase(), boNot);
				if(sValue2 != null && sValue2.length() > 0) {
					String sClause2 = buildClause(mapFields, "sn=" + sValue2.toUpperCase(), boNot);
					if(sClause2 != null && sClause2.length() > 0) {
						if(sResult.length() > 0) {
							sResult = "(" + sResult + " AND " + sClause2 + ")";
						}
						else {
							sResult = sClause2;
						}
					}
					return sResult;
				}
			}
			return "";
		}
		boolean boCantBeALike = false;
		if(sKey.equalsIgnoreCase("uniqueMember") || sKey.endsWith("Membership")) {
			sValue = "'" + getFirstName(sValue).replace("'", "''") + "'";
		}
		else
		if(sKey.equalsIgnoreCase("birthday") || sKey.equalsIgnoreCase("notBefore") ||
				sKey.equalsIgnoreCase("notAfter") || sKey.equalsIgnoreCase("lastAccess")) {
			sValue = normalizeDate(sValue);
			boCantBeALike = true;
		}
		else
		if(sKey.equalsIgnoreCase("employeeNumber")) {
			sValue = normalizeInteger(sValue);
			boCantBeALike = true;
		}
		else {
			sValue = "'" + sValue.replace("'", "''") + "'";
		}
		if(!boCantBeALike && boLike) {
			sValue = sValue.replace('*', '%');
			if(boNot) {
				return sField + " NOT LIKE " + sValue;
			}
			else {
				return sField + " LIKE " + sValue;
			}
		}
		if(boNot) {
			return sField + " <> " + sValue;
		}
		return sField + " = " + sValue;
	}
	
	public static
	String buildExpression(Map<String,String> mapFields, String sFilter)
	{
		return buildExpression(mapFields, sFilter, '\0', false);
	}
	
	public static
	String buildExpression(Map<String,String> mapFields, String sFilter, char cOp, boolean boNot)
	{
		if(sFilter == null || sFilter.length() < 3) return "";
		String sResult = "";
		char c0 = sFilter.charAt(0);
		if(c0 == '&' || c0 == '|') {
			sResult += "(" + buildExpression(mapFields, sFilter.substring(1), c0, boNot) + ")";
		}
		else
		if(c0 == '!') {
			sResult += buildExpression(mapFields, sFilter.substring(1), c0, !boNot);
		}
		else
		if(c0 == '(') {
			String sOp = "";
			if(cOp == '&') sOp = boNot ? " OR " : " AND ";
			else
			if(cOp == '|') sOp = boNot ? " AND " : " OR ";
			List<String> listLeaves = getLeaves(sFilter);
			int iLeaves = listLeaves.size();
			for(int i = 0; i < iLeaves; i++) {
				String sLeaf = (String) listLeaves.get(i);
				String sExpression = buildExpression(mapFields, sLeaf, cOp, boNot);
				if(sExpression.length() > 0) {
					sResult += sExpression;
					if(i < iLeaves - 1) sResult += sOp;
				}
			}
		}
		else {
			sResult += Utils.buildClause(mapFields, sFilter, boNot);
		}
		if(sResult.endsWith(" AND ")) sResult = sResult.substring(0, sResult.length() - 5);
		if(sResult.endsWith(" OR "))  sResult = sResult.substring(0, sResult.length() - 4);
		if(sResult.equals("()")) return "";
		return sResult;
	}
	
	public static
	List<String> getLeaves(String sFilter)
	{
		List<String> listResult = new ArrayList<String>();
		int iLength = sFilter.length();
		int iOpenClose = 0;
		int iStartLeaf = 0;
		for(int i = 0; i < iLength; i++) {
			char c = sFilter.charAt(i);
			if(c == '(') {
				if(iOpenClose == 0) {
					iStartLeaf = i + 1;
				}
				iOpenClose++;
			}
			if(c == ')') {
				iOpenClose--;
				if(iOpenClose == 0) {
					if(iStartLeaf > 0 && i > iStartLeaf) {
						listResult.add(sFilter.substring(iStartLeaf, i));
						iStartLeaf = 0;
					}
				}
			}
		}
		return listResult;
	}
}
