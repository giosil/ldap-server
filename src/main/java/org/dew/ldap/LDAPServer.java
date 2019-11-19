package org.dew.ldap;

import java.io.File;
import java.net.*;

import java.util.*;

import javax.naming.Context;
import javax.naming.ldap.InitialLdapContext;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import java.util.logging.*;

public 
class LDAPServer extends Thread
{
	private static Logger oLogger = Logger.getLogger(LDAPServer.class.getName());
	
	public final static String sVERSION = "1.0.0"; 
	public static String sSTART_TIMESTAMP;
	
	protected ServerSocket serverSocket;
	protected Class<?> classOfLDAPSession;
	protected int iPort;
	protected List<ALDAPSession> listOfALDAPSession;
	
	public 
	LDAPServer(Class<?> classOfLDAPSession, int iPort)
	{
		this.classOfLDAPSession = classOfLDAPSession;
		this.iPort = iPort;
		this.listOfALDAPSession = new ArrayList<ALDAPSession>();
	}
	
	// SSL (porta 636)
	// -Djavax.net.ssl.keyStore=mykeystore -Djavax.net.ssl.keyStorePassword=secret
	// keytool -keystore mykeystore -keypasswd secret -genkey -keyalg RSA -alias mycert
	public static
	void main(String args[]) 
	{
		initLogger();
		Class<?> classOfLDAPSession = DummyLDAPSession.class;
		int iPort = 389;
		if(args.length > 0) {
			if(args[0].equalsIgnoreCase("stop")) {
				if(args.length < 5) {
					System.err.println("Usage: LDAPServer stop Host Port UserDN Password");
					return;
				}
				try{ iPort = Integer.parseInt(args[2]); } catch(Exception ex){}
				sendStopRequest(args[1], iPort, args[3], args[4]);
				return;
			}
			else {
				try{ iPort = Integer.parseInt(args[0]); } catch(Exception ex){}
				if(args.length == 2 && args[1].equalsIgnoreCase("dummy")) {
					classOfLDAPSession = DummyLDAPSession.class;
				}
			}
		}
		LDAPServer ldapServer = new LDAPServer(classOfLDAPSession, iPort);
		System.out.println("Start LDAP Server " + sVERSION + " at " + iPort + "...");
		System.out.println("Session handler: " + classOfLDAPSession.getCanonicalName());
		ldapServer.start();
	}
	
	public 
	void run()
	{
		if(classOfLDAPSession == null) {
			System.err.println("classOfLDAPSession is null");
			oLogger.severe("classOfLDAPSession is null");
			return;
		}
		sSTART_TIMESTAMP = Utils.dateTimeToTimeStamp(new java.util.Date());
		try {
			if(iPort == 636) {
				// SSL
				// -Djavax.net.ssl.keyStore=mykeystore -Djavax.net.ssl.keyStorePassword=secret
				// keytool -keystore mykeystore -keypasswd secret -genkey -keyalg RSA -alias mycert
				ServerSocketFactory sslSocketFactory = SSLServerSocketFactory.getDefault();
				serverSocket = sslSocketFactory.createServerSocket(iPort);
			}
			else {
				serverSocket = new ServerSocket(iPort);
			}
			System.out.println("LDAP Server started");
			oLogger.fine("LDAP Server started");
			do {
				Socket socket = serverSocket.accept();
				oLogger.fine("create newInstance of " + classOfLDAPSession.getName() + "...");
				Object ldapSession = classOfLDAPSession.newInstance();
				if(ldapSession instanceof ALDAPSession) {
					((ALDAPSession) ldapSession).setLDAPServer(this);
					((ALDAPSession) ldapSession).setSocket(socket);
					((ALDAPSession) ldapSession).start();
				}
				else {
					System.err.println(classOfLDAPSession.getName() + " is not a ALDAPSession.");
					oLogger.severe(classOfLDAPSession.getName() + " is not a ALDAPSession.");
				}
			}
			while(true);
		}
		catch(Exception ex){
			oLogger.severe("Exception in LDAPServer.run: " + ex);
		}
		finally {
			System.out.println("LDAP Server stopped.");
			oLogger.fine("LDAP Server stopped.");
			System.exit(0);
		}
	}
	
	public final
	void onBeginSession(ALDAPSession aLDAPSession)
	{
		listOfALDAPSession.add(aLDAPSession);
	}
	
	public final
	void onEndSession(ALDAPSession aLDAPSession)
	{
		listOfALDAPSession.remove(aLDAPSession);
	}
	
	public final
	int countSessions()
	{
		return listOfALDAPSession != null ? listOfALDAPSession.size() : 0;
	}
	
	public final
	void closeServerSocket()
	{
		System.out.println("LDAP Server stopping...");
		try {
			if(listOfALDAPSession != null) {
				for(int i = 0; i < listOfALDAPSession.size(); i++) {
					ALDAPSession aLDAPSession = listOfALDAPSession.get(i);
					aLDAPSession.closeSocket();
				}
			}
		}
		catch(Exception ex) {
			oLogger.severe("Exception in LDAPServer.closeServerSocket: " + ex);
		}
		try {
			serverSocket.close();
		}
		catch(Exception ex) {
			oLogger.severe("Exception in LDAPServer.closeServerSocket: " + ex);
		}
	}
	
	public static  
	void sendStopRequest(String sHost, int iPort, String sUserDN, String sPassword) 
	{
		String sCfgLdapURL = null;
		if(iPort == 636) {
			sCfgLdapURL  = "ldaps://" + sHost + ":" + iPort;
		}
		else {
			sCfgLdapURL  = "ldap://" + sHost + ":" + iPort;
		}
		
		Hashtable<String,String> environment = new Hashtable<String,String>();
		environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		if(sCfgLdapURL.startsWith("ldaps")) environment.put(Context.SECURITY_PROTOCOL,    "ssl");
		environment.put(Context.PROVIDER_URL,            sCfgLdapURL);
		environment.put(Context.SECURITY_AUTHENTICATION, "simple");
		environment.put(Context.SECURITY_PRINCIPAL,      sUserDN);
		environment.put(Context.SECURITY_CREDENTIALS,    sPassword);
		
		InitialLdapContext ldapContext = null;
		try {
			// Connecting to LDAP server...
			System.out.println("Connecting to LDAP Server...");
			ldapContext = new InitialLdapContext(environment, null);
			ldapContext.close();
			System.out.println("LDAP Server stopped.");
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
	}
	
	private static
	void initLogger()
	{
		try {
			String sLog = LDAPServerConfig.getProperty(LDAPServerConfig.sCONF_LOG);
			boolean boLevelSevere = false;
			if(sLog != null && sLog.length() > 0) {
				sLog = sLog.trim(); 
				char c0 = sLog.charAt(0);
				if(c0 == 'e' || c0 == 'E' || c0 == 's' || c0 == 'S') {
					boLevelSevere = true;
				}
			}
			String sUserHome = System.getProperty("user.home");
			String sLogFolder = sUserHome + File.separator + "log";
			File fileLogFolder = new File(sLogFolder);
			if(!fileLogFolder.exists()) fileLogFolder.mkdirs();
			Handler handler = new FileHandler("%h/log/ldapserver%g.log", 2 * 1024 * 1024, 10, true);
			handler.setFormatter(new LogFormatter());
			Logger.getLogger("org.dew.ldap").addHandler(handler);
			if(boLevelSevere) {
				Logger.getLogger("org.dew.ldap").setLevel(Level.SEVERE);
			}
			else {
				Logger.getLogger("org.dew.ldap").setLevel(Level.ALL);
			}
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
	}
}
