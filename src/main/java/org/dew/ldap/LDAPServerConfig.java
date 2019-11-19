package org.dew.ldap;

import java.util.*;
import java.io.*;
import java.net.*;

import java.util.Date;

public
class LDAPServerConfig
{
  public static Properties config = new Properties();

  private static boolean boConfigFileLoaded = false;
  private static String sResultLoading = "OK";

  public static boolean LOG_ENABLED = true;

  public final static String sCONF_JDBC_DRIVER   = "jdbc.driver";
  public final static String sCONF_JDBC_URL      = "jdbc.url";
  public final static String sCONF_JDBC_USER     = "jdbc.user";
  public final static String sCONF_JDBC_PWD      = "jdbc.password";
  public final static String sCONF_JDBC_IDLE     = "jdbc.idle";
  public final static String sCONF_JDBC_TEST     = "jdbc.test";
  public final static String sCONF_LOG           = "log";
  public final static String sCONF_STOP_USER     = "stop.user";
  public final static String sCONF_STOP_PASS     = "stop.pass";
  public final static String sCONF_JW_URL        = "jateway.url";
  public final static String sCONF_JW_BAK        = "jateway.bak";
  public final static String sCONF_JW_ID_CLIENT  = "jateway.id_client";
  public final static String sCONF_JW_ID_SERVER  = "jateway.id_server";
  public final static String sCONF_JW_SESSION    = "jateway.session";
  public final static String sCONF_CLOSE_ON_BIND = "close_on_bind";
  
  static {
	  if(!loadConfigInClassPath()) {
		  loadConfig();
	  }
  }

  public static
  boolean loadConfig()
  {
    String sUserHome = System.getProperty("user.home");
    String sPathFile = sUserHome + File.separator + "cfg" + File.separator + "ldap_server.cfg";
    FileInputStream fis = null;
    try {
      fis = new FileInputStream(sPathFile);
      config = new Properties();
      config.load(fis);
      boConfigFileLoaded = true;
      String sLog = config.getProperty(sCONF_LOG);
      LOG_ENABLED = true;
      if(sLog == null || sLog.trim().length() == 0) {
    	  LOG_ENABLED = false;
      }
      else {
    	  sLog = sLog.trim();
    	  char c0 = sLog.charAt(0);
		  if(c0 == '0' || c0 == 'n' || c0 == 'N') {
			  LOG_ENABLED = false;
		  }
	  }
      sResultLoading = "File " + sPathFile + " loaded.";
    }
    catch (FileNotFoundException ex) {
      sResultLoading = "File " + sPathFile + " not found.";
      return false;
    }
    catch (IOException ioex) {
      sResultLoading = "IOException during load " + sPathFile + ": " + ioex;
      return false;
    }
    finally {
    	if(fis != null) try{ fis.close(); } catch(Exception ex) {}
    }
    return true;
  }

  public static
  boolean loadConfigInClassPath()
  {
    try {
	  URL url = Thread.currentThread().getContextClassLoader().getResource("ldap_server.cfg");
	  if(url == null) return false;
	  InputStream in = url.openStream();
      config = new Properties();
      config.load(in);
      in.close();
      boConfigFileLoaded = true;
      String sLog = config.getProperty(sCONF_LOG);
      LOG_ENABLED = true;
      if(sLog == null || sLog.trim().length() == 0) {
    	  LOG_ENABLED = false;
      }
      else {
    	  sLog = sLog.trim();
    	  char c0 = sLog.charAt(0);
		  if(c0 == '0' || c0 == 'n' || c0 == 'N') {
			  LOG_ENABLED = false;
		  }
	  }
      sResultLoading = "File loaded from classpath.";
    }
    catch (Exception ex) {
      sResultLoading = "Exception during load: " + ex;
      return false;
    }
    return true;
  }

  public static
  boolean isConfigFileLoaded()
  {
    return boConfigFileLoaded;
  }

  public static
  String getResultLoading()
  {
    return sResultLoading;
  }

  public static
  String getProperty(String sKey)
  {
    return config.getProperty(sKey);
  }

  public static
  String getProperty(String sKey, String sDefault)
  {
    return config.getProperty(sKey, sDefault);
  }

  public static
  Date getDateProperty(String sKey, Date oDefault)
  {
    String sValue = (String) config.get(sKey);
    if(sValue == null)
      return oDefault;

    int iDate = (new Integer(sValue)).intValue();

    if(iDate > 0){
      int iYear  = iDate / 10000;
      int iMonth = (iDate % 10000) / 100;
      iMonth -= 1;
      int iDay   = (iDate % 10000) % 100;
      return new GregorianCalendar(iYear, iMonth, iDay).getTime();
    }

    return oDefault;
  }

  public static
  boolean getBooleanProperty(String sKey, boolean bDefault)
  {
    String sValue = (String) config.get(sKey);
    if(sValue == null)
      return bDefault;
    else if(sValue.equals("0") ||
            sValue.equalsIgnoreCase("false") ||
            sValue.equalsIgnoreCase("N"))
      return false;

    return true;
  }

  public static
  int getIntProperty(String sKey, int iDefault)
  {
    String sValue = (String) config.get(sKey);
    if(sValue == null)
      return iDefault;

    return (new Integer(sValue)).intValue();
  }

  public static
  double getDoubleProperty(String sKey, double dDefault)
  {
    String sValue = (String) config.get(sKey);
    if(sValue == null)
      return dDefault;

    return (new Double(sValue)).doubleValue();
  }
}
