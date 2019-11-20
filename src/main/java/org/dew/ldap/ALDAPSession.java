package org.dew.ldap;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.Logger;

public abstract  
class ALDAPSession extends Thread implements ILDAPConstants
{
	private static Logger oLogger = Logger.getLogger(ALDAPSession.class.getName());
	
	// ActiveDirectory
	protected static String defaultNamingContext = LDAPServerConfig.getProperty(LDAPServerConfig.sCONF_DEF_NAME_CTX);
	// (ANR = Ambiguous Name Resolution)
	protected static String lastANRFilter;
	
	public static final String sOU_UTENTI = "ou=users";
	
	private LDAPServer _ldapServer;
	
	protected Socket _socket;
	protected String _sLDAPUserId;
	protected String _sLDAPPassword;
	protected String _sDomain;
	
	protected boolean _boLoggedIn  = false;
	protected boolean _boLDAPAdminLoggedIn = false;
	protected boolean _boAnonymous = false;
	
	protected int _lastProtocolOp = 0;
	protected int _lastMessageId  = 0;
	
	protected static Map<String,List<String>> organizationalUnitClass = new HashMap<String,List<String>>();
	protected static Map<String,List<String>> domainComponentClass    = new HashMap<String,List<String>>();
	protected static Map<String,List<String>> subschemaClass          = new HashMap<String,List<String>>();
	protected static Map<String,List<String>> groupOfUniqueNamesClass = new HashMap<String,List<String>>();
	protected static Map<String,List<String>> inetOrgPersonClass      = new HashMap<String,List<String>>();
	static {
		Utils.put(organizationalUnitClass, "objectClass", "organizationaUnit",     "top");
		Utils.put(domainComponentClass,    "objectClass", "dcObject",              "top");
		Utils.put(subschemaClass,          "objectClass", "subentry", "subschema", "top");
		Utils.put(groupOfUniqueNamesClass, "objectClass", "groupOfUniqueNames",    "top");
		Utils.put(inetOrgPersonClass,      "objectClass", "extensibleObject", "inetOrgPerson", "organizationalPerson", "person", "top");
	}
	
	// ActiveDirectory
	protected static Map<String,List<String>> organizationalUnitCategory = new HashMap<String,List<String>>();
	protected static Map<String,List<String>> person                     = new HashMap<String,List<String>>();
	static {
		Utils.put(organizationalUnitCategory, "objectCategory", "organizationalUnit");
		Utils.put(person,                     "objectCategory", "person");
	}
	
	public 
	ALDAPSession()
	{
	}
	
	public
	void setLDAPServer(LDAPServer ldapServer)
	{
		this._ldapServer = ldapServer;
	}
	
	public
	void setSocket(Socket socket)
	{
		this._socket = socket;
	}
	
	public
	int getLastProtocolOp() 
	{
		return _lastProtocolOp;
	}
	
	public
	int getLastMessageId() 
	{
		return _lastMessageId;
	}
	
	public
	void closeSocket()
	{
		try{ _socket.close();  } catch(Exception ex) {}
		_ldapServer.onEndSession(this);
	}
	
	public
	void run()
	{
		_ldapServer.onBeginSession(this);
		InputStream  is  = null;
		OutputStream os = null;
		try {
			_socket.setTcpNoDelay(true);
			is = _socket.getInputStream();
			os = _socket.getOutputStream();
			LDAPMessage ldapMessage = null;
			while((ldapMessage = BER.parseMessage(is)) != null) {
				if(!handleMessage(ldapMessage, os)) {
					break;
				}
			}
		}
		catch(Throwable th) {
			oLogger.severe("Exception in ALDAPSession.run: " + th);
		}
		finally {
			try { unbind(null, null); } catch(Exception ex) {}
			if(os != null) try{ os.close(); } catch(Exception ex) {}
			if(is != null) try{ is.close(); } catch(Exception ex) {}
			try{ _socket.close();  } catch(Exception ex) {}
			_ldapServer.onEndSession(this);
		}
	}
	
	protected
	boolean handleMessage(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		if(LDAPServerConfig.LOG_ENABLED) {
			oLogger.fine("handleMessage " + ldapMessage + "... ");
		}
		int iProtocolOp = ldapMessage.getProtocolOp();
		if(iProtocolOp == LDAP_REQ_BIND) {
			return bind(ldapMessage, os);
		}
		
		_lastProtocolOp = iProtocolOp;
		_lastMessageId  = ldapMessage.getId();
		
		if(_boAnonymous) {
			if(iProtocolOp == LDAP_REQ_SEARCH) {
				if(!defaultSearch(ldapMessage, os)) {
					BER.sendResult(os, ldapMessage.getId(), LDAP_RES_SEARCH_RESULT, LDAP_NO_SUCH_OBJECT);
					return true;
				}
			}
			else
			if(iProtocolOp == LDAP_REQ_UNBIND) {
				return false;
			}
		}
		if(!_boLoggedIn) {
			if(iProtocolOp == LDAP_REQ_SEARCH) {
				if(rootDSEAndSchemaSearch(ldapMessage, os)) {
					return true;
				}
			}
			else
			if(iProtocolOp == LDAP_REQ_ABANDON) {
				return abandon(ldapMessage, os);
			}
			BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_OPERATIONS_ERROR);
			return false;
		}
		try {
			switch (iProtocolOp) {
				case LDAP_REQ_UNBIND:
					return unbind(ldapMessage, os);
				case LDAP_REQ_ABANDON:
					return abandon(ldapMessage, os);
				case LDAP_REQ_SEARCH:
					if(defaultSearch(ldapMessage, os)) return true;
					return search(ldapMessage,  os);
				case LDAP_REQ_MODIFY:
					return modify(ldapMessage,  os);
				case LDAP_REQ_ADD:
					return add(ldapMessage,     os);
				case LDAP_REQ_DELETE:
					return delete(ldapMessage,  os);
				case LDAP_REQ_MODRDN:
					return modrdn(ldapMessage,  os);
				case LDAP_REQ_COMPARE:
					return compare(ldapMessage, os);
			}
		}
		catch(Exception ex) {
			ex.printStackTrace();
			BER.sendResult(os, ldapMessage.getId(), Utils.getResProtocolOp(iProtocolOp), LDAP_OPERATIONS_ERROR);
			return false;
		}
		return false;
	}
	
	protected
	boolean bind(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		_boLoggedIn = false;
		
		String sName = ldapMessage.getLastStringControl(1);
		String sPass = ldapMessage.getLastStringControl(0);
		if(sPass == null || sPass.length() == 0) {
			_boAnonymous = true;
			BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_SUCCESS);
			return true;
		}
		if(sName == null) {
			BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_INVALID_CREDENTIALS);
			return false;
		}
		if(_boLDAPAdminLoggedIn) {
			if("top".equals(sName)) {
				sName = "uid=?," + sOU_UTENTI + ",dc=" + _sDomain;
			}
		}
		if(sName.startsWith("uid=")) {
			int iIndexDomain = sName.indexOf(",dc=");
			if(iIndexDomain <= 0) {
				BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_INVALID_CREDENTIALS);
				return false;
			}
			_sLDAPUserId = sName.substring(4, iIndexDomain).trim();
			_sDomain = sName.substring(iIndexDomain + 4).trim();
		}
		else {
			// ActiveDirectory
			_sLDAPUserId = sName + "," + sOU_UTENTI;
			if(defaultNamingContext != null && defaultNamingContext.length() > 0) {
				_sDomain = defaultNamingContext;
			}
		}
		
		if(_sDomain != null && _sDomain.equals("ldapserver")) {
			String sUserStop = LDAPServerConfig.getProperty(LDAPServerConfig.sCONF_STOP_USER, "stop");
			String sPassStop = LDAPServerConfig.getProperty(LDAPServerConfig.sCONF_STOP_PASS, "pwstop");
			if(_sLDAPUserId.equals(sUserStop) && sPass.equals(sPassStop)) {
				BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_SUCCESS);
				_ldapServer.closeServerSocket();
				return false;
			}
		}
		
		int iSep = _sLDAPUserId.indexOf(',');
		if(iSep < 0) {
			// Admin server LDAP login
			if(loginLDAPAdmin(_sLDAPUserId, sPass)) {
				_boLoggedIn = true;
				_boLDAPAdminLoggedIn = true;
				_sLDAPPassword = sPass;
				BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_SUCCESS);
				return true;
			}
			else {
				_boLoggedIn = false;
				_boLDAPAdminLoggedIn = false;
				BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_INVALID_CREDENTIALS);
				return false;
			}
		}
		else {
			// User login
			String sUserId = _sLDAPUserId.substring(0, iSep);
			if(login(sUserId, sPass)) {
				_boLoggedIn = true;
				_boLDAPAdminLoggedIn = false;
				BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_SUCCESS);
				String sCfgDomainCloseOnBind = "dc_" + _sDomain + "." + LDAPServerConfig.sCONF_CLOSE_ON_BIND;
				boolean boCloseOnBind = LDAPServerConfig.getBooleanProperty(sCfgDomainCloseOnBind, false);
				return !boCloseOnBind;
			}
			else {
				_boLoggedIn = false;
				_boLDAPAdminLoggedIn = false;
				BER.sendResult(os, ldapMessage.getId(), LDAP_RES_BIND, LDAP_INVALID_CREDENTIALS);
				return false;
			}
		}
	}
	
	protected 
	boolean unbind(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		if(_boLoggedIn) {
			if(_boLDAPAdminLoggedIn) {
				logoutLDAPAdmin();
			}
			else {
				logout();
			}
		}
		_boLoggedIn = false;
		_boLDAPAdminLoggedIn = false;
		return false;
	}
	
	protected abstract boolean loginLDAPAdmin(String sUserId, String sPass) throws Exception;
	
	protected abstract void logoutLDAPAdmin();
	
	protected abstract boolean login(String sUserId, String sPass) throws Exception;
	
	protected abstract void logout();
	
	protected abstract List<String> getNamingContexts();
	
	protected abstract boolean search(LDAPMessage ldapMessage, OutputStream os) throws Exception;
	
	protected
	List<String> getMonitorCounters()
	{
		return new ArrayList<String>();
	}
	
	protected
	int getMonitorCounter(String sMonitorCounter)
	{
		return 0;
	}
	
	protected 
	boolean abandon(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		return true;
	}
	
	protected 
	boolean modify(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		BER.sendResult(os, ldapMessage.getId(), LDAP_RES_MODIFY, LDAP_OPERATIONS_ERROR);
		return false;
	}
	
	protected 
	boolean add(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		BER.sendResult(os, ldapMessage.getId(), LDAP_RES_ADD, LDAP_OPERATIONS_ERROR);
		return false;
	}
	
	protected 
	boolean delete(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		BER.sendResult(os, ldapMessage.getId(), LDAP_RES_DELETE, LDAP_OPERATIONS_ERROR);
		return false;
	}
	
	protected 
	boolean modrdn(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		BER.sendResult(os, ldapMessage.getId(), LDAP_RES_MODRDN, LDAP_OPERATIONS_ERROR);
		return false;
	}
	
	protected 
	boolean compare(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		BER.sendResult(os, ldapMessage.getId(), LDAP_RES_COMPARE, LDAP_OPERATIONS_ERROR);
		return false;
	}
	
	protected 
	boolean rootDSEAndSchemaSearch(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		int iMsgId = ldapMessage.getId();
		String sBaseObject = ldapMessage.getStringControl(0);
		List<Object> listAttributes = ldapMessage.getLastListControl(0);
		String sFirstAttribute = "";
		if(listAttributes != null && listAttributes.size() > 0) {
			sFirstAttribute = (String) listAttributes.get(0);
		}
		if(sBaseObject == null || sBaseObject.length() == 0) {
			if(sFirstAttribute.equals("*")) {
				BER.sendSearchResult(os, iMsgId, "", getRootAttributes(null, listAttributes));
			}
			BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
			return true;
		}
		else
		if(sBaseObject.equalsIgnoreCase("cn=schema")) {
			BER.sendResourceContent(os, iMsgId, "schema.dat");
			BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
			return true;
		}
		return false;
	}
	
	protected 
	boolean defaultSearch(LDAPMessage ldapMessage, OutputStream os)
		throws Exception
	{
		int iMsgId           = ldapMessage.getId();
		String sBaseObject   = ldapMessage.getStringControl(0);
		String sBaseObjectLC = sBaseObject.toLowerCase();
		int iScope           = ldapMessage.getIntControl(1);
		List<Object> listAttributes = ldapMessage.getLastListControl(0);
		String sFilter       = ldapMessage.getLastStringControl(1);
		String sFirstAttribute = "";
		if(listAttributes != null && listAttributes.size() > 0) {
			sFirstAttribute = (String) listAttributes.get(0);
		}
		boolean boNoAttributes = Utils.isNoAttributes(listAttributes);
		
		if(sBaseObject == null || sBaseObject.length() == 0) {
			if(sFirstAttribute.equals("*") && _sDomain != null) {
				BER.sendSearchResult(os, iMsgId, "dc=" + _sDomain, getRootAttributes(domainComponentClass, listAttributes));
			}
			else {
				BER.sendSearchResult(os, iMsgId, "", getRootAttributes(null, listAttributes));
			}
			BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
			return true;
		}
		else
		if(sBaseObject.equalsIgnoreCase("cn=schema")) {
			if(iScope == 0) {
				BER.sendResourceContent(os, iMsgId, "schema.dat");
			}
			else
			if(sFilter.toLowerCase().indexOf("objectclass=subschema") >= 0) {
				BER.sendSearchResult(os, iMsgId, "cn=schema", getSchemaAttributes(subschemaClass, listAttributes));
			}
			else {
				BER.sendResourceContent(os, iMsgId, "schema.dat");
			}
			BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
			return true;
		}
		else
		if(sBaseObjectLC.endsWith("cn=monitor")) {
			if(sBaseObject.equalsIgnoreCase("cn=monitor")) {
				BER.sendSearchResult(os, iMsgId, sBaseObject, getMonitorAttributes(listAttributes));
			}
			else
			if(sBaseObject.equalsIgnoreCase("cn=start,cn=time,cn=monitor")) {
				Map<String,List<String>> map = new HashMap<String,List<String>>();
				Utils.put(map, "objectClass",   "monitoredObject", "top");
				Utils.put(map, "monitorTimestamp", LDAPServer.sSTART_TIMESTAMP);
				BER.sendSearchResult(os, iMsgId, sBaseObject, map);
			}
			else
			if(sBaseObject.equalsIgnoreCase("cn=current,cn=time,cn=monitor")) {
				Map<String,List<String>> map = new HashMap<String,List<String>>();
				Utils.put(map, "objectClass",   "monitoredObject", "top");
				Utils.put(map, "monitorTimestamp", Utils.dateTimeToTimeStamp(new java.util.Date()));
				BER.sendSearchResult(os, iMsgId, sBaseObject, map);
			}
			else
			if(sBaseObject.equalsIgnoreCase("cn=sessions,cn=monitor")) {
				BER.sendSearchResult(os, iMsgId, sBaseObject, getMonitorCounterAttributes(_ldapServer.countSessions()));
			}
			else
			if(sBaseObject.equalsIgnoreCase("cn=threads,cn=monitor")) {
				BER.sendSearchResult(os, iMsgId, sBaseObject, getMonitorCounterAttributes(Thread.getAllStackTraces().size()));
			}
			else {
				if(sBaseObjectLC.startsWith("cn=") && sBaseObjectLC.endsWith(",cn=monitor")) {
					int iMonitorCounter = getMonitorCounter(sBaseObject);
					if(iMonitorCounter >= 0) {
						BER.sendSearchResult(os, iMsgId, sBaseObject, getMonitorCounterAttributes(iMonitorCounter));
					}
				}
			}
			BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
			return true;
		}
		else
		if(sFirstAttribute.equals("+")) {
			// Attributi operazionali non gestiti
			BER.sendSearchResult(os, iMsgId, sBaseObject);
			BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
			return true;
		}
		else
		if(sBaseObject.equals("uid=" + _sLDAPUserId + ",dc=" + _sDomain)) {
			if(iScope == 0) {
				if(boNoAttributes) {
					BER.sendSearchResult(os, iMsgId, sBaseObject, inetOrgPersonClass);
				}
				else {
					BER.sendSearchResult(os, iMsgId, sBaseObject, getAdminitratorAttributes());
				}
			}
			BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
			return true;
		}
		return false;
	}
	
	protected
	Map<String,List<String>> getRootAttributes(Map<String,List<String>> mapDefault, List<Object> listAttributes)
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>();
		if(mapDefault != null && !mapDefault.isEmpty()) {
			map.putAll(mapDefault);
		}
		if(listAttributes.size() == 0 || listAttributes.contains("namingContexts")) {
			Utils.put(map, "namingContexts", getNamingContexts());
		}
		if(listAttributes.size() == 0 || listAttributes.contains("defaultNamingContext")) {
			// ActiveDirectory
			if(defaultNamingContext != null) {
				Utils.put(map, "defaultNamingContext", "dc=" + defaultNamingContext);
			}
		}
		if(listAttributes.size() == 0 || listAttributes.contains("supportedExtension")) {
			Utils.put(map, "supportedExtension", "2.16.840.1.113730.3.5.7");
		}
		if(listAttributes.size() == 0 || listAttributes.contains("supportedControl")) {
			Utils.put(map, "supportedControl", "2.16.840.1.113730.3.4.2");
		}
		if(listAttributes.size() == 0 || listAttributes.contains("supportedLdapVersion")) {
			Utils.put(map, "supportedLdapVersion", "3");
		}
		if(listAttributes.size() == 0 || listAttributes.contains("subschemaSubentry")) {
			Utils.put(map, "subschemaSubentry", "cn=schema");
		}
		if(listAttributes.size() == 0 || listAttributes.contains("supportedSASLMechanisms")) {
			Utils.put(map, "supportedSASLMechanisms", "SIMPLE");
		}
		if(listAttributes.size() == 0 || listAttributes.contains("vendorName")) {
			Utils.put(map, "vendorName", "ISED S.p.A.");
		}
		if(listAttributes.size() == 0 || listAttributes.contains("vendorVersion")) {
			Utils.put(map, "vendorVersion", LDAPServer.sVERSION);
		}
		return map;
	}
	
	protected
	Map<String,List<String>> getSchemaAttributes(Map<String,List<String>> mapDefault, List<Object> listAttributes)
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>();
		if(mapDefault != null && !mapDefault.isEmpty()) {
			map.putAll(mapDefault);
		}
		if(listAttributes.size() == 0 || listAttributes.contains("createTimestamp")) {
			Utils.put(map, "createTimestamp", Utils.dateTimeToTimeStamp(new Date()));
		}
		if(listAttributes.size() == 0 || listAttributes.contains("modifyTimestamp")) {
			Utils.put(map, "modifyTimestamp", Utils.dateTimeToTimeStamp(new Date()));
		}
		return map;
	}
	
	protected
	Map<String,List<String>> getMonitorAttributes(List<Object> listAttributes)
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>();
		Utils.put(map, "objectClass",   "monitorServer", "top");
		Utils.put(map, "monitoredInfo", "LDAP Server " + LDAPServer.sVERSION);
		List<String> listDescription = new ArrayList<String>();
		listDescription.add("Available objects");
		listDescription.add("cn=start,cn=time,cn=monitor");
		listDescription.add("cn=current,cn=time,cn=monitor");
		listDescription.add("Sono disponibili i seguenti counter");
		listDescription.add("cn=sessions,cn=monitor");
		listDescription.add("cn=threads,cn=monitor");
		List<String> listMonitorCounters = getMonitorCounters();
		for(String sMonitorCounter : listMonitorCounters) {
			listDescription.add(sMonitorCounter);
		}
		Utils.put(map, "description", listDescription);
		return map;
	}
	
	protected static
	Map<String,List<String>> getMonitorCounterAttributes(int iMonitorCounter)
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>();
		Utils.put(map, "objectClass",   "monitorCounter", "top");
		Utils.put(map, "monitorCounter", String.valueOf(iMonitorCounter));
		return map;
	}
	
	protected static
	Map<String,List<String>> getAliasAttributes(String sAliasedObjectName)
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>();
		Utils.put(map, "objectClass",       "alias", "top");
		Utils.put(map, "aliasedObjectName", sAliasedObjectName);
		return map;
	}
	
	protected
	Map<String,List<String>> getAdminitratorAttributes()
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>(inetOrgPersonClass);
		Utils.put(map, "uid",          _sLDAPUserId);
		Utils.put(map, "userPassword", Utils.getDigestSHA(_sLDAPPassword));
		Utils.put(map, "givenName",    _sLDAPUserId);
		Utils.put(map, "sn",           "administrator");
		Utils.put(map, "cn",           "system administrator");
		Utils.put(map, "description",  "The administrator");
		Utils.put(map, "displayName",  "Directory Superuser");
		return map;
	}
	
	protected static
	Map<String,List<String>> groupOfUniqueNames(String sName, String sUniqueMember)
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>(groupOfUniqueNamesClass);
		Utils.put(map, "cn", sName);
		if(sUniqueMember != null && sUniqueMember.length() > 0) {
			List<String> listUniqueMember = new ArrayList<String>(1);
			listUniqueMember.add(sUniqueMember);
			map.put("uniqueMember", listUniqueMember);
		}
		return map;
	}
	
	protected static
	Map<String,List<String>> groupOfUniqueNames(String sName, String sUniqueMember, List<Object> listAttributes)
	{
		Map<String,List<String>> map = new HashMap<String,List<String>>(groupOfUniqueNamesClass);
		Utils.put(map, "cn", sName);
		// ActiveDirectory
		Utils.checkPut(listAttributes, map, "member",            sUniqueMember);
		Utils.checkPut(listAttributes, map, "dn",                sUniqueMember);
		Utils.checkPut(listAttributes, map, "distinguishedName", sUniqueMember);
		Utils.checkPut(listAttributes, map, "objectSid",         sName);
		if(sUniqueMember != null && sUniqueMember.length() > 0) {
			List<String> listUniqueMember = new ArrayList<String>(1);
			listUniqueMember.add(sUniqueMember);
			map.put("uniqueMember", listUniqueMember);
		}
		return map;
	}
}
