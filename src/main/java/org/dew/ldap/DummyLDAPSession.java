package org.dew.ldap;

import java.io.OutputStream;
import java.util.*;
import java.util.logging.*;

public 
class DummyLDAPSession extends ALDAPSession 
{
  private static Logger oLogger = Logger.getLogger(ALDAPSession.class.getName());
  
  public static final String sOU_RUOLI     = "ou=roles";
  public static final String sOU_GRUPPI    = "ou=groups";
  public static final String sOU_ABILITAZ  = "ou=grants";
  public static final String sOU_STRUTTURE = "ou=structures";
  public static final String sOU_CONFIG    = "ou=configurations";
  public static final String sOU_UTENTI    = "ou=users";
  
  public static Map<String,String> mapFields = new HashMap<String, String>();
  static {
    mapFields.put("sn",                  "U.COGNOME");
    mapFields.put("description",         "U.CODICEFISCALE");
    mapFields.put("givenName",           "U.NOME");
    mapFields.put("name",                "U.NOME");
    mapFields.put("birthday",            "U.DATANASCITA");
    mapFields.put("sex",                 "U.SESSO");
    mapFields.put("uid",                 "C.ID_CREDENZIALE");
    mapFields.put("mail",                "U.EMAIL");
    mapFields.put("telephoneNumber",     "U.TELEFONO");
    mapFields.put("mobile",              "U.CELLULARE");
    mapFields.put("ou",                  "U.RIFERIMENTO");
    mapFields.put("title",               "U.TITOLO");
    mapFields.put("employeeNumber",      "U.ID_UTENTE");
    mapFields.put("description",         "U.CODICEFISCALE");
    mapFields.put("uniqueMember",        "C.ID_CREDENZIALE");
    mapFields.put("notBefore",           "C.INIZIOVALIDITA");
    mapFields.put("notAfter",            "C.FINEVALIDITA");
    mapFields.put("lastAccess",          "C.DATA_ULT_ACC");
    mapFields.put("roleMembership",      "C.ID_RUOLO");
    mapFields.put("groupMembership",     "CG.ID_GRUPPO");
    mapFields.put("grantMembership",     "CA.ID_ABILITAZIONE");
    mapFields.put("structureMembership", "CS.ID_STRUTTURA");
  }
  
  protected String lastUserFound;
  
  public DummyLDAPSession()
  {
  }
  
  protected
  boolean loginLDAPAdmin(String sUserId, String sPass)
    throws Exception 
  {
    if(LDAPServerConfig.LOG_ENABLED) oLogger.fine("loginLDAPAdmin(" + sUserId + ", " + sPass + ")");
    if(sUserId != null && sUserId.equals("?")) {
      sUserId = lastUserFound;
    }    
    return sUserId.equalsIgnoreCase(sPass);
  }
  
  protected
  void logoutLDAPAdmin()
  {
    if(LDAPServerConfig.LOG_ENABLED) oLogger.fine("logoutLDAPAdmin()...");
  }
  
  protected
  boolean login(String sUserId, String sPass)
    throws Exception 
  {
    if(LDAPServerConfig.LOG_ENABLED) oLogger.fine("login(" + sUserId + ", " + sPass + ")");
    return sUserId.equalsIgnoreCase(sPass);
  }
  
  protected
  void logout()
  {
    if(LDAPServerConfig.LOG_ENABLED) oLogger.fine("logout()...");
  }
  
  protected
  List<String> getNamingContexts()
  {
    List<String> listResult  = new ArrayList<String>();
    listResult.add("dc=test");
    return listResult;
  }
  
  protected
  List<String> getMonitorCounters()
  {
    List<String> listResult  = new ArrayList<String>();
    listResult.add("cn=Current,cn=Connections,cn=Servizio,cn=Monitor");
    listResult.add("cn=Total,cn=Connections,cn=Servizio,cn=Monitor");
    return listResult;
  }

  protected
  int getMonitorCounter(String sMonitorCounter)
  {
    return 0;
  }
  
  protected
  boolean search(LDAPMessage ldapMessage, OutputStream os)
    throws Exception
  {
    String sBaseObject   = ldapMessage.getStringControl(0);
    String sBaseObjectLC = sBaseObject.toLowerCase();
    int iScope           = ldapMessage.getIntControl(1);
    int iSizeLimit       = ldapMessage.getIntControl(2);
    int iMsgId           = ldapMessage.getId();
    String sFilter       = ldapMessage.getLastStringControl(1);
    List<Object> attribs = ldapMessage.getLastListControl(0);
    Utils.normalizeAttributes(attribs);
    
    boolean boNoAttributes  = Utils.isNoAttributes(attribs);
    boolean boFindPerson    = Utils.findPerson(sFilter);
    boolean boFindGroupOfUN = Utils.findGroupOfUniqueNames(sFilter);
    String  sFilterCategory = Utils.getFilterCategory(sFilter);
    
    List<String> listItems = null;
    String sDomainLC       = _sDomain != null ? _sDomain.toLowerCase() : "";
    
    String sFiltroUtenti = null;
    if(sFilter != null && sFilter.startsWith("(")) {
      // ActiveDirectory
      if(sFilter.startsWith("(&(objectcategory=person)(")) {
        sFilter = sFilter.substring(25, sFilter.length()-1);
        // Ambiguous Name Resolution
        lastANRFilter = Utils.getFilterValue(sFilter, "anr");
      }
      sFiltroUtenti = Utils.buildExpression(mapFields, sFilter);
    }
    boolean boFiltroUtenti = sFiltroUtenti != null && sFiltroUtenti.length() > 0;
    if(iSizeLimit < 4) iSizeLimit = 1000;
    
    if(sBaseObject.startsWith("cn=Deleted Objects")) {
      BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
    }
    else if(sBaseObject.equalsIgnoreCase("dc=" + _sDomain)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, Utils.buildAttributes(sBaseObject, domainComponentClass));
      }
      else {
        if(boFiltroUtenti || boFindPerson) {
          if(iScope == 2) {
            listItems = getUtenti(_sDomain, sFiltroUtenti, iSizeLimit);
            for(String sItem : listItems) {
              if(boNoAttributes) {
                BER.sendSearchResult(os, iMsgId, "uid=" + sItem + "," + sOU_UTENTI + ",dc=" + _sDomain, inetOrgPersonClass);
              }
              else {
                BER.sendSearchResult(os, iMsgId, "uid=" + sItem + "," + sOU_UTENTI + ",dc=" + _sDomain, readUtente(sItem, _sDomain, attribs));
              }
            }
          }
        }
        else if(boFindGroupOfUN) {
          if(iScope == 2) {
            // Benche' anche i ruoli, le abilitazioni e le strutture siano groupOfUniqueNamesClass
            // con tali criteri di ricerca si restituiscono soltanto i gruppi. 
            listItems  = getGruppi(_sDomain, iSizeLimit);
            for(String sItem : listItems) {
              if(boNoAttributes) {
                BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_GRUPPI + ",dc=" + _sDomain, groupOfUniqueNamesClass);
              }
              else {
                BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_GRUPPI + ",dc=" + _sDomain, readGruppo(sItem, _sDomain, iSizeLimit));
              }
            }
          }
        }
        else if(sFilterCategory != null && sFilterCategory.equalsIgnoreCase("organizationalUnit")) {
          // ActiveDirectory
          String sFilterNameOrg  = Utils.getFilterValue(sFilter, "Name");
          if(iScope == 2 && sFilterNameOrg != null && sFilterNameOrg.equalsIgnoreCase("users")) {
            BER.sendSearchResult(os, iMsgId, sOU_UTENTI    + ",dc=" + _sDomain, organizationalUnitCategory);
            listItems = getUtenti(_sDomain, sFiltroUtenti, iSizeLimit);
            for(String sItem : listItems) {
              BER.sendSearchResult(os, iMsgId, "dn=" + sItem + "," + sOU_UTENTI + ",dc=" + _sDomain, readUtente(sItem, _sDomain, attribs));
            }
          }
          else {
            BER.sendSearchResult(os, iMsgId, sOU_UTENTI    + ",dc=" + _sDomain, organizationalUnitCategory);
          }
        }
        else if(sFilterCategory != null && sFilterCategory.equalsIgnoreCase("User")) {
          // ActiveDirectory
          String sUid  = Utils.getDistinguishedNameUid(sFilter);
          if(iScope == 2 && sUid != null && sUid.length() > 0) {
            List<String> listRuoli = getRuoli(_sDomain, sUid, iSizeLimit);
            for(String sRuolo : listRuoli) {
              if(boNoAttributes) {
                BER.sendSearchResult(os, iMsgId, "cn=" + sRuolo + "," + sOU_UTENTI + ",dc=" + _sDomain, groupOfUniqueNamesClass);
              }
              else {
                String sUniqueMember = "uid=" + sUid + "," + sOU_UTENTI + ",dc=" + _sDomain;
                BER.sendSearchResult(os, iMsgId, "cn=" + sRuolo + "," + sOU_UTENTI + ",dc=" + _sDomain, groupOfUniqueNames(sRuolo, sUniqueMember));
              }
            }
            BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
          }
        }
        else {
          BER.sendSearchResult(os, iMsgId, "uid=" + _sLDAPUserId + "," + sBaseObject, inetOrgPersonClass);
          BER.sendSearchResult(os, iMsgId, sOU_RUOLI     + ",dc=" + _sDomain, organizationalUnitClass);
          BER.sendSearchResult(os, iMsgId, sOU_GRUPPI    + ",dc=" + _sDomain, organizationalUnitClass);
          BER.sendSearchResult(os, iMsgId, sOU_ABILITAZ  + ",dc=" + _sDomain, organizationalUnitClass);
          BER.sendSearchResult(os, iMsgId, sOU_STRUTTURE + ",dc=" + _sDomain, organizationalUnitClass);
          BER.sendSearchResult(os, iMsgId, sOU_CONFIG    + ",dc=" + _sDomain, organizationalUnitClass);
          BER.sendSearchResult(os, iMsgId, sOU_UTENTI    + ",dc=" + _sDomain, organizationalUnitClass);
        }
      }
    }
    else
    if(sBaseObject.equalsIgnoreCase(sOU_RUOLI + ",dc=" + _sDomain)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, Utils.buildAttributes(sOU_RUOLI, organizationalUnitClass));
      }
      else {
        if(boFiltroUtenti) {
          listItems = getRuoli(_sDomain, sFiltroUtenti, iSizeLimit);
        }
        else {
          listItems = getRuoli(_sDomain, iSizeLimit);
        }
        for(String sItem : listItems) {
          if(boNoAttributes) {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_RUOLI + ",dc=" + _sDomain, groupOfUniqueNamesClass);
          }
          else {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_RUOLI + ",dc=" + _sDomain, readRuolo(sItem, _sDomain, iSizeLimit));
          }
        }
      }
    }
    else
    if(sBaseObject.equalsIgnoreCase(sOU_ABILITAZ + ",dc=" + _sDomain)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, Utils.buildAttributes(sOU_ABILITAZ, organizationalUnitClass));
      }
      else {
        if(boFiltroUtenti) {
          listItems = getAbilitazioni(_sDomain, sFiltroUtenti, iSizeLimit);
        }
        else {
          listItems = getAbilitazioni(_sDomain, iSizeLimit);
        }
        for(String sItem : listItems) {
          if(boNoAttributes) {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_ABILITAZ + ",dc=" + _sDomain, groupOfUniqueNamesClass);
          }
          else {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_ABILITAZ + ",dc=" + _sDomain, readAbilitazione(sItem, _sDomain, iSizeLimit));
          }
        }
      }
    }
    else
    if(sBaseObject.equalsIgnoreCase(sOU_GRUPPI + ",dc=" + _sDomain)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, Utils.buildAttributes(sOU_GRUPPI, organizationalUnitClass));
      }
      else {
        if(boFiltroUtenti) {
          listItems = getGruppi(_sDomain, sFiltroUtenti, iSizeLimit);
        }
        else {
          listItems = getGruppi(_sDomain, iSizeLimit);
        }
        for(String sItem : listItems) {
          if(boNoAttributes) {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_GRUPPI + ",dc=" + _sDomain, groupOfUniqueNamesClass);
          }
          else {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_GRUPPI + ",dc=" + _sDomain, readGruppo(sItem, _sDomain, iSizeLimit));
          }
        }
      }
    }
    else
    if(sBaseObject.equalsIgnoreCase(sOU_STRUTTURE + ",dc=" + _sDomain)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, Utils.buildAttributes(sOU_STRUTTURE, organizationalUnitClass));
      }
      else {
        if(boFiltroUtenti) {
          listItems = getStrutture(_sDomain, sFiltroUtenti, iSizeLimit);
        }
        else {
          listItems = getStrutture(_sDomain, iSizeLimit);
        }
        for(String sItem : listItems) {
          if(boNoAttributes) {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_STRUTTURE + ",dc=" + _sDomain, groupOfUniqueNamesClass);
          }
          else {
            BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sOU_STRUTTURE + ",dc=" + _sDomain, readStruttura(sItem, _sDomain, iSizeLimit));
          }
        }
      }
    }
    else
    if(sBaseObject.equalsIgnoreCase(sOU_CONFIG + ",dc=" + _sDomain)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, Utils.buildAttributes(sOU_CONFIG, organizationalUnitClass));
      }
      else {
        listItems = getConfigurazioni(_sDomain, iSizeLimit);
        for(String sItem : listItems) {
          BER.sendSearchResult(os, iMsgId, "ou=" + sItem + "," + sOU_CONFIG + ",dc=" + _sDomain, organizationalUnitClass);
        }
      }
    }
    else
    if(sBaseObject.equalsIgnoreCase(sOU_UTENTI + ",dc=" + _sDomain)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, Utils.buildAttributes(sOU_UTENTI, organizationalUnitClass));
      }
      else {
        if(boFiltroUtenti) {
          listItems = getUtenti(_sDomain, sFiltroUtenti, iSizeLimit);
        }
        else
        if(sFilter == null || sFilter.length() == 0 || sFilter.toLowerCase().startsWith("(objectclass=")) {
          listItems = getUtenti(_sDomain, null, iSizeLimit);
        }
        else {
          // Lettura gruppi realm LDAP (i gruppi sono mappati con i ruoli)
          if(boFindGroupOfUN) {
            List<String> listRuoli = getRuoli(_sDomain, iSizeLimit);
            for(String sRuolo : listRuoli) {
              if(boNoAttributes) {
                BER.sendSearchResult(os, iMsgId, "cn=" + sRuolo + "," + sOU_UTENTI + ",dc=" + _sDomain, groupOfUniqueNamesClass);
              }
              else {
                BER.sendSearchResult(os, iMsgId, "cn=" + sRuolo + "," + sOU_UTENTI + ",dc=" + _sDomain, groupOfUniqueNames(sRuolo, null));
              }
            }
            BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
            return true;
          }
          else {
            String sUid = Utils.getUniqueMemberUid(sFilter);
            if(sUid == null || sUid.length() == 0) {
              // ActiveDirectory
              sUid = Utils.getMemberUid(sFilter);
            }
            if(sUid != null && sUid.length() > 0) {
              List<String> listRuoli = getRuoli(_sDomain, "C.ID_CREDENZIALE='" + sUid.replace("'", "''") + "'", iSizeLimit);
              for(String sRuolo : listRuoli) {
                if(boNoAttributes) {
                  BER.sendSearchResult(os, iMsgId, "cn=" + sRuolo + "," + sOU_UTENTI + ",dc=" + _sDomain, groupOfUniqueNamesClass);
                }
                else {
                  String sUniqueMember = "uid=" + sUid + "," + sOU_UTENTI + ",dc=" + _sDomain;
                  BER.sendSearchResult(os, iMsgId, "cn=" + sRuolo + "," + sOU_UTENTI + ",dc=" + _sDomain, groupOfUniqueNames(sRuolo, sUniqueMember));
                }
              }
              BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
              return true;
            }
            else {
              // ActiveDirectory
              sUid = Utils.getDistinguishedNameUid(sFilter);
              if(sUid == null || sUid.length() == 0) {
                sUid = Utils.getUserPrincipalName(sFilter);
              }
              if(sUid != null && sUid.length() > 0) {
                BER.sendSearchResult(os, iMsgId, "uid=" + sUid + "," + sOU_UTENTI + ",dc=" + _sDomain, readUtente(sUid, _sDomain, attribs));
                BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
                return true;
              }
            }
          }
          listItems = new ArrayList<String>();
        }
        for(String sItem : listItems) {
          if(boNoAttributes) {
            BER.sendSearchResult(os, iMsgId, "uid=" + sItem + "," + sOU_UTENTI + ",dc=" + _sDomain, inetOrgPersonClass);
          }
          else {
            BER.sendSearchResult(os, iMsgId, "uid=" + sItem + "," + sOU_UTENTI + ",dc=" + _sDomain, readUtente(sItem, _sDomain, attribs));
          }
        }
      }
    }
    else
    if(sBaseObjectLC.endsWith("," + sOU_RUOLI + ",dc=" + sDomainLC)) {
      if(iScope == 0) BER.sendSearchResult(os, iMsgId, sBaseObject, readRuolo(Utils.getFirstName(sBaseObject), _sDomain, iSizeLimit));
    }
    else
    if(sBaseObjectLC.endsWith("," + sOU_ABILITAZ + ",dc=" + sDomainLC)) {
      if(iScope == 0) BER.sendSearchResult(os, iMsgId, sBaseObject, readAbilitazione(Utils.getFirstName(sBaseObject), _sDomain, iSizeLimit));
    }
    else
    if(sBaseObjectLC.endsWith("," + sOU_GRUPPI + ",dc=" + sDomainLC)) {
      if(iScope == 0) BER.sendSearchResult(os, iMsgId, sBaseObject, readGruppo(Utils.getFirstName(sBaseObject), _sDomain, iSizeLimit));
    }
    else
    if(sBaseObjectLC.endsWith("," + sOU_STRUTTURE + ",dc=" + sDomainLC)) {
      if(iScope == 0) {
        BER.sendSearchResult(os, iMsgId, sBaseObject, readStruttura(Utils.getFirstName(sBaseObject), _sDomain, iSizeLimit));
      }
      else {
        listItems = getSubStrutture(_sDomain, Utils.getFirstName(sBaseObject), iSizeLimit);
        for(String sItem : listItems) {
          BER.sendSearchResult(os, iMsgId, "cn=" + sItem + "," + sBaseObject, groupOfUniqueNamesClass);
        }
      }
    }
    else
    if(sBaseObjectLC.endsWith("," + sOU_CONFIG + "," + "dc=" + sDomainLC)) {
      if(iScope == 0) BER.sendSearchResult(os, iMsgId, sBaseObject, readConfigurazione(Utils.getFirstName(sBaseObject), _sDomain));
    }
    else
    if(sBaseObjectLC.endsWith("," + sOU_UTENTI + "," + "dc=" + sDomainLC)) {
      if(iScope == 0) {
        if(boNoAttributes) {
          if(existUtente(Utils.getFirstName(sBaseObject), _sDomain)) {
            BER.sendSearchResult(os, iMsgId, "uid=" + Utils.getFirstName(sBaseObject) + "," + sOU_UTENTI + ",dc=" + _sDomain, inetOrgPersonClass);
          }
        }
        else {
          BER.sendSearchResult(os, iMsgId, "uid=" + Utils.getFirstName(sBaseObject) + "," + sOU_UTENTI + ",dc=" + _sDomain, readUtente(Utils.getFirstName(sBaseObject), _sDomain, attribs));
        }
      }
    }
    else {
      BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_NO_SUCH_OBJECT);
      return true;
    }
    BER.sendResult(os, iMsgId, LDAP_RES_SEARCH_RESULT, LDAP_SUCCESS);
    return true;
  }
  
  protected 
  boolean modify(LDAPMessage ldapMessage, OutputStream os)
    throws Exception
  {
    String sBaseObject = ldapMessage.getStringControl(0);
    List<Object> listAttributesToModify = ldapMessage.getListControl(1);
    Map<String,Object> mapAttributesToReplace = Utils.getAttributesToModify(listAttributesToModify, LDAP_MOD_REPLACE);
    System.out.println("modify sBaseObject = " + sBaseObject);
    System.out.println("modify mapAttributesToReplace = " + mapAttributesToReplace);
    // Alcuni portali richiedono un'operazione di modifica, che di fatto non viene eseguita.
    // Tuttavia si restituisce LDAP_SUCCESS per proseguire con l'operazione di autenticazione.
    BER.sendResult(os, ldapMessage.getId(), LDAP_RES_MODIFY, LDAP_SUCCESS);
    return true;
  }
  
  private static
  List<String> getRuoli(String sIdServizio, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    listResult.add("admin");
    listResult.add("oper");
    listResult.add("guest");
    return listResult;
  }
  
  private static
  List<String> getRuoli(String sIdServizio, String sFiltroUtenti, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    String sIdCredenziale = getIdCredenziale(sFiltroUtenti);
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("bianchi")) {
      listResult.add("admin");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("rossi")) {
      listResult.add("oper");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("verdi")) {
      listResult.add("guest");
    }
    return listResult;
  }
  
  private static
  List<String> getGruppi(String sIdServizio, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    listResult.add("CC");
    listResult.add("HD");
    listResult.add("ST");
    return listResult;
  }
  
  private static
  List<String> getGruppi(String sIdServizio, String sFiltroUtenti, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    String sIdCredenziale = getIdCredenziale(sFiltroUtenti);
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("bianchi")) {
      listResult.add("ST");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("rossi")) {
      listResult.add("HD");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("verdi")) {
      listResult.add("CC");
    }
    return listResult;
  }
  
  private static
  List<String> getAbilitazioni(String sIdServizio, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    listResult.add("read");
    listResult.add("write");
    listResult.add("create");
    listResult.add("delete");
    return listResult;
  }
  
  private static
  List<String> getAbilitazioni(String sIdServizio, String sFiltroUtenti, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    String sIdCredenziale = getIdCredenziale(sFiltroUtenti);
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("bianchi")) {
      listResult.add("create");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("rossi")) {
      listResult.add("write");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("verdi")) {
      listResult.add("read");
    }
    return listResult;
  }
  
  private static
  List<String> getConfigurazioni(String sIdServizio, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    listResult.add("prod");
    listResult.add("form");
    listResult.add("test");
    return listResult;
  }
  
  private static
  List<String> getStrutture(String sIdServizio, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    listResult.add("azienda");
    return listResult;
  }
  
  private static
  List<String> getStrutture(String sIdServizio, String sFiltroUtenti, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    String sIdCredenziale = getIdCredenziale(sFiltroUtenti);
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("bianchi")) {
      listResult.add("direzione,cn=azienda");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("rossi")) {
      listResult.add("sviluppo,cn=azienda");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("verdi")) {
      listResult.add("callcenter,cn=azienda");
    }
    return listResult;
  }
  
  private static
  List<String> getSubStrutture(String sIdServizio, String sIdStrutturaPadre, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    if(!sIdStrutturaPadre.equalsIgnoreCase("azienda")) return listResult;
    listResult.add("direzione");
    listResult.add("sviluppo");
    listResult.add("callcenter");
    return listResult;
  }
  
  protected
  List<String> getUtenti(String sIdServizio, String sFiltroUtenti, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    
    String sIdCredenziale = getIdCredenziale(sFiltroUtenti);
    
    if(sFiltroUtenti != null && sFiltroUtenti.length() > 0) {
      sIdCredenziale = getIdCredenziale(sFiltroUtenti);
    }
    else if(lastANRFilter != null && lastANRFilter.length() > 0) {
      // Active Directory
      // Ambiguous Name Resolution
      sIdCredenziale = lastANRFilter;
      lastANRFilter  = null;
    }
    
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("bianchi")) {
      listResult.add("bianchi");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("rossi")) {
      listResult.add("rossi");
    }
    else
    if(sIdCredenziale != null && sIdCredenziale.equalsIgnoreCase("verdi")) {
      listResult.add("verdi");
    }
    else 
    if(sFiltroUtenti == null || sFiltroUtenti.length() == 0) {
      listResult.add("bianchi");
      listResult.add("rossi");
      listResult.add("verdi");
    }
    if(listResult != null && listResult.size() > 0) {
      lastUserFound = listResult.get(0);
    }
    
    return listResult;
  }
  
  private static
  List<String> getUtentiPerRuolo(String sIdServizio, String sIdRuolo, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    if(sIdRuolo.equalsIgnoreCase("admin")) listResult.add("bianchi");
    if(sIdRuolo.equalsIgnoreCase("oper"))  listResult.add("rossi");
    if(sIdRuolo.equalsIgnoreCase("guest")) listResult.add("rossi");
    return listResult;
  }
  
  private static
  List<String> getUtentiPerGruppo(String sIdServizio, String sIdGruppo, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    if(sIdGruppo.equalsIgnoreCase("ST")) listResult.add("bianchi");
    if(sIdGruppo.equalsIgnoreCase("HD")) listResult.add("rossi");
    if(sIdGruppo.equalsIgnoreCase("CC")) listResult.add("verdi");
    return listResult;
  }
  
  private static
  List<String> getUtentiPerAbilitazione(String sIdServizio, String sIdAbilitazione, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    if(sIdAbilitazione.equalsIgnoreCase("create")) listResult.add("bianchi");
    if(sIdAbilitazione.equalsIgnoreCase("write"))  listResult.add("rossi");
    if(sIdAbilitazione.equalsIgnoreCase("read"))   listResult.add("verdi");
    return listResult;
  }
  
  private static
  List<String> getUtentiPerStruttura(String sIdServizio, String sIdStruttura, int iSizeLimit)
  {
    List<String> listResult = new ArrayList<String>();
    if(sIdStruttura.equalsIgnoreCase("direzione"))  listResult.add("bianchi");
    if(sIdStruttura.equalsIgnoreCase("sviluppo"))   listResult.add("rossi");
    if(sIdStruttura.equalsIgnoreCase("callcenter")) listResult.add("verdi");
    return listResult;
  }
  
  private static
  Map<String,List<String>> readRuolo(String sName, String sIdServizio, int iSizeLimit)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(groupOfUniqueNamesClass);
    Utils.put(map, "cn", sName);
    Utils.put(map, "description", "role " + sName);
    List<String> listUtenti = getUtentiPerRuolo(sIdServizio, sName, iSizeLimit);
    List<String> listUniqueMember = new ArrayList<String>(listUtenti.size());
    for(String sUtente : listUtenti) {
      listUniqueMember.add("uid=" + sUtente + "," + sOU_UTENTI + ",dc=" + sIdServizio);
    }
    map.put("uniqueMember", listUniqueMember);
    return map;
  }
  
  private static
  Map<String,List<String>> readAbilitazione(String sName, String sIdServizio, int iSizeLimit)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(groupOfUniqueNamesClass);
    Utils.put(map, "cn", sName);
    Utils.put(map, "description", "grant " + sName);
    List<String> listUtenti = getUtentiPerAbilitazione(sIdServizio, sName, iSizeLimit);
    List<String> listUniqueMember = new ArrayList<String>(listUtenti.size());
    for(String sUtente : listUtenti) {
      listUniqueMember.add("uid=" + sUtente + "," + sOU_UTENTI + ",dc=" + sIdServizio);
    }
    map.put("uniqueMember", listUniqueMember);
    return map;
  }
  
  private static
  Map<String,List<String>> readGruppo(String sName, String sIdServizio, int iSizeLimit)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(groupOfUniqueNamesClass);
    Utils.put(map, "cn", sName);
    Utils.put(map, "description", "group " + sName);
    List<String> listUtenti = getUtentiPerGruppo(sIdServizio, sName, iSizeLimit);
    List<String> listUniqueMember = new ArrayList<String>(listUtenti.size());
    for(String sUtente : listUtenti) {
      listUniqueMember.add("uid=" + sUtente + "," + sOU_UTENTI + ",dc=" + sIdServizio);
    }
    map.put("uniqueMember", listUniqueMember);
    return map;
  }
  
  private static
  Map<String,List<String>> readStruttura(String sName, String sIdServizio, int iSizeLimit)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(groupOfUniqueNamesClass);
    Utils.put(map, "cn", sName);
    Utils.put(map, "description", "structure " + sName);
    List<String> listUtenti = getUtentiPerStruttura(sIdServizio, sName, iSizeLimit);
    List<String> listUniqueMember = new ArrayList<String>(listUtenti.size());
    for(String sUtente : listUtenti) {
      listUniqueMember.add("uid=" + sUtente + "," + sOU_UTENTI + ",dc=" + sIdServizio);
    }
    map.put("uniqueMember", listUniqueMember);
    return map;
  }
  
  private static
  Map<String,List<String>> readConfigurazione(String sName, String sIdServizio)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(organizationalUnitClass);
    Utils.put(map, "ou", sName);
    Utils.put(map, "description", sName);
    return map;
  }
  
  protected
  boolean existUtente(String sIdCredenziale, String sIdServizio)
  {
    boolean boResult = sIdCredenziale.equalsIgnoreCase("bianchi") || sIdCredenziale.equalsIgnoreCase("rossi") || sIdCredenziale.equalsIgnoreCase("verdi");
    if(boResult) lastUserFound = sIdCredenziale;
    return boResult;
  }
  
  private static
  Map<String,List<String>> readUtente(String sIdCredenziale, String sIdServizio, List<Object> listAttributes)
  {
    if(sIdCredenziale.equalsIgnoreCase("bianchi")) {
      return readBianchi(sIdCredenziale, sIdServizio, listAttributes);
    }
    else
    if(sIdCredenziale.equalsIgnoreCase("rossi")) {
      return readRossi(sIdCredenziale, sIdServizio, listAttributes);
    }
    else
    if(sIdCredenziale.equalsIgnoreCase("verdi")) {
      return readVerdi(sIdCredenziale, sIdServizio, listAttributes);
    }
    return null;
  }
  
  private static
  Map<String,List<String>> readBianchi(String sIdCredenziale, String sIdServizio, List<Object> listAttributes)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(inetOrgPersonClass);
    
    // ActiveDirectory
    Utils.put(map, "objectClass",       "extensibleObject",  "inetOrgPerson", "organizationalPerson", "person", "top");
    Utils.put(map, "objectCategory",    "person");
    Utils.checkPut(listAttributes, map, "distinguishedName", "uid=bianchi," + sOU_UTENTI + ",dc=" + sIdServizio);
    Utils.checkPut(listAttributes, map, "objectSid",         "1");
    Utils.checkPut(listAttributes, map, "objectSID",         "1");
    Utils.checkPut(listAttributes, map, "userPrincipalName", "bianchi");
    Utils.checkPut(listAttributes, map, "whenCreated",       "20191119");
    Utils.checkPut(listAttributes, map, "isDeleted",         "false");
    Utils.checkPut(listAttributes, map, "pwdLastSet",        "20191119");
    Utils.checkPut(listAttributes, map, "employeeID",        "1");
    // LDAP attributes
    Utils.checkPut(listAttributes, map, "uid",               "bianchi");
    Utils.checkPut(listAttributes, map, "employeeNumber",    "1");
    Utils.checkPut(listAttributes, map, "ou",                "test");
    Utils.checkPut(listAttributes, map, "description",       "ANTONIO BIANCHI");
    Utils.checkPut(listAttributes, map, "cn",                "ANTONIO BIANCHI");
    Utils.checkPut(listAttributes, map, "displayName",       "ANTONIO BIANCHI");
    Utils.checkPut(listAttributes, map, "sn",                "BIANCHI");
    Utils.checkPut(listAttributes, map, "givenName",         "ANTONIO");
    Utils.checkPut(listAttributes, map, "birthday",          "19750815");
    Utils.checkPut(listAttributes, map, "sex",               "M");
    Utils.checkPut(listAttributes, map, "telephoneNumber",   "06-0000001");
    Utils.checkPut(listAttributes, map, "mobile",            "349-0000001");
    Utils.checkPut(listAttributes, map, "title",             "SIG");
    Utils.checkPut(listAttributes, map, "mail",              "bianchi@test.com");
    Utils.checkPut(listAttributes, map, "userPassword",      Utils.getDigestSHA("bianchi"));
    
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("roleMembership")) {
      List<String> listRoleMembership = new ArrayList<String>();
      listRoleMembership.add("cn=admin," + sOU_RUOLI + ",dc=" + sIdServizio);
      map.put("roleMembership", listRoleMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("groupMembership")) {
      // Gruppi
      List<String> listGroupMembership = new ArrayList<String>();
      listGroupMembership.add("cn=ST," + sOU_GRUPPI + ",dc=" + sIdServizio);
      map.put("groupMembership", listGroupMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("grantMembership")) {
      // Abilitazioni
      List<String> listGrantMembership = new ArrayList<String>();
      listGrantMembership.add("cn=create," + sOU_ABILITAZ + ",dc=" + sIdServizio);
      map.put("grantMembership", listGrantMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("structureMembership")) {
      // Strutture
      List<String> listStructureMembership = new ArrayList<String>();
      listStructureMembership.add("cn=direzione,cn=azienda," + sOU_STRUTTURE + ",dc=" + sIdServizio);
      map.put("structureMembership", listStructureMembership); // Back Link
    }
    return map;
  }
  
  private static
  Map<String,List<String>> readRossi(String sIdCredenziale, String sIdServizio, List<Object> listAttributes)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(inetOrgPersonClass);
    
    // ActiveDirectory
    Utils.put(map, "objectClass",       "extensibleObject",  "inetOrgPerson", "organizationalPerson", "person", "top");
    Utils.put(map, "objectCategory",    "person");
    Utils.checkPut(listAttributes, map, "distinguishedName", "uid=rossi," + sOU_UTENTI + ",dc=" + sIdServizio);
    Utils.checkPut(listAttributes, map, "objectSid",         "2");
    Utils.checkPut(listAttributes, map, "objectSID",         "2");
    Utils.checkPut(listAttributes, map, "userPrincipalName", "rossi");
    Utils.checkPut(listAttributes, map, "whenCreated",       "20191119");
    Utils.checkPut(listAttributes, map, "isDeleted",         "false");
    Utils.checkPut(listAttributes, map, "pwdLastSet",        "20191119");
    Utils.checkPut(listAttributes, map, "employeeID",        "2");
    // LDAP attributes
    Utils.checkPut(listAttributes, map, "uid",               "rossi");
    Utils.checkPut(listAttributes, map, "employeeNumber",    "2");
    Utils.checkPut(listAttributes, map, "ou",                "test");
    Utils.checkPut(listAttributes, map, "description",       "MARIO ROSSI");
    Utils.checkPut(listAttributes, map, "cn",                "MARIO ROSSI");
    Utils.checkPut(listAttributes, map, "displayName",       "MARIO ROSSI");
    Utils.checkPut(listAttributes, map, "sn",                "ROSSI");
    Utils.checkPut(listAttributes, map, "givenName",         "MARIO");
    Utils.checkPut(listAttributes, map, "birthday",          "19741119");
    Utils.checkPut(listAttributes, map, "sex",               "M");
    Utils.checkPut(listAttributes, map, "telephoneNumber",   "06-0000002");
    Utils.checkPut(listAttributes, map, "mobile",            "349-0000002");
    Utils.checkPut(listAttributes, map, "title",             "SIG");
    Utils.checkPut(listAttributes, map, "mail",              "rossi@test.com");
    Utils.checkPut(listAttributes, map, "userPassword",      Utils.getDigestSHA("rossi"));
    
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("roleMembership")) {
      List<String> listRoleMembership = new ArrayList<String>();
      listRoleMembership.add("cn=oper," + sOU_RUOLI + ",dc=" + sIdServizio);
      map.put("roleMembership", listRoleMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("groupMembership")) {
      // Gruppi
      List<String> listGroupMembership = new ArrayList<String>();
      listGroupMembership.add("cn=HD," + sOU_GRUPPI + ",dc=" + sIdServizio);
      map.put("groupMembership", listGroupMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("grantMembership")) {
      // Abilitazioni
      List<String> listGrantMembership = new ArrayList<String>();
      listGrantMembership.add("cn=write," + sOU_ABILITAZ + ",dc=" + sIdServizio);
      map.put("grantMembership", listGrantMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("structureMembership")) {
      // Strutture
      List<String> listStructureMembership = new ArrayList<String>();
      listStructureMembership.add("cn=sviluppo,cn=azienda," + sOU_STRUTTURE + ",dc=" + sIdServizio);
      map.put("structureMembership", listStructureMembership); // Back Link
    }
    return map;
  }
  
  private static
  Map<String,List<String>> readVerdi(String sIdCredenziale, String sIdServizio, List<Object> listAttributes)
  {
    Map<String,List<String>> map = new HashMap<String,List<String>>(inetOrgPersonClass);
    
    // ActiveDirectory
    Utils.put(map, "objectClass",       "extensibleObject",  "inetOrgPerson", "organizationalPerson", "person", "top");
    Utils.put(map, "objectCategory",    "person");
    Utils.checkPut(listAttributes, map, "distinguishedName", "uid=verdi," + sOU_UTENTI + ",dc=" + sIdServizio);
    Utils.checkPut(listAttributes, map, "objectSid",         "3");
    Utils.checkPut(listAttributes, map, "objectSID",         "3");
    Utils.checkPut(listAttributes, map, "userPrincipalName", "verdi");
    Utils.checkPut(listAttributes, map, "whenCreated",       "20191119");
    Utils.checkPut(listAttributes, map, "isDeleted",         "false");
    Utils.checkPut(listAttributes, map, "pwdLastSet",        "20191119");
    Utils.checkPut(listAttributes, map, "employeeID",        "3");
    // LDAP attributes
    Utils.checkPut(listAttributes, map, "uid",               "verdi");
    Utils.checkPut(listAttributes, map, "employeeNumber",    "3");
    Utils.checkPut(listAttributes, map, "ou",                "test");
    Utils.checkPut(listAttributes, map, "description",       "GIUSEPPE VERDI");
    Utils.checkPut(listAttributes, map, "cn",                "GIUSEPPE VERDI");
    Utils.checkPut(listAttributes, map, "displayName",       "GIUSEPPE VERDI");
    Utils.checkPut(listAttributes, map, "sn",                "VERDI");
    Utils.checkPut(listAttributes, map, "givenName",         "GIUSEPPE");
    Utils.checkPut(listAttributes, map, "birthday",          "19780503");
    Utils.checkPut(listAttributes, map, "sex",               "M");
    Utils.checkPut(listAttributes, map, "telephoneNumber",   "06-0000003");
    Utils.checkPut(listAttributes, map, "mobile",            "349-0000003");
    Utils.checkPut(listAttributes, map, "title",             "SIG");
    Utils.checkPut(listAttributes, map, "mail",              "verdi@test.com");
    Utils.checkPut(listAttributes, map, "userPassword",      Utils.getDigestSHA("verdi"));
    
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("roleMembership")) {
      List<String> listRoleMembership = new ArrayList<String>();
      listRoleMembership.add("cn=guest," + sOU_RUOLI + ",dc=" + sIdServizio);
      map.put("roleMembership", listRoleMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("groupMembership")) {
      // Gruppi
      List<String> listGroupMembership = new ArrayList<String>();
      listGroupMembership.add("cn=CC," + sOU_GRUPPI + ",dc=" + sIdServizio);
      map.put("groupMembership", listGroupMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("grantMembership")) {
      // Abilitazioni
      List<String> listGrantMembership = new ArrayList<String>();
      listGrantMembership.add("cn=read," + sOU_ABILITAZ + ",dc=" + sIdServizio);
      map.put("grantMembership", listGrantMembership); // Back Link
    }
    if(listAttributes == null || listAttributes.size() == 0 || listAttributes.contains("structureMembership")) {
      // Strutture
      List<String> listStructureMembership = new ArrayList<String>();
      listStructureMembership.add("cn=callcenter,cn=azienda," + sOU_STRUTTURE + ",dc=" + sIdServizio);
      map.put("structureMembership", listStructureMembership); // Back Link
    }
    return map;
  }
  
  private static
  String getIdCredenziale(String sFilter)
  {
    if(sFilter == null) return null;
    String sField = "ID_CREDENZIALE = '";
    int iBegin = sFilter.indexOf(sField);
    if(iBegin >= 0) {
      iBegin += sField.length();
      int iEnd = sFilter.indexOf('\'', iBegin);
      if(iEnd > 0 && iEnd > iBegin) {
        return sFilter.substring(iBegin, iEnd);
      }
    }
    sField = "MAIL = '";
    iBegin = sFilter.indexOf(sField);
    if(iBegin >= 0) {
      iBegin += sField.length();
      int iEnd = sFilter.indexOf('\'', iBegin);
      if(iEnd > 0 && iEnd > iBegin) {
        String sMail = sFilter.substring(iBegin, iEnd);
        int iAt = sMail.indexOf('@');
        if(iAt > 0) {
          return sMail.substring(0, iAt);
        }
      }
    }
    sField = "COGNOME = '";
    iBegin = sFilter.indexOf(sField);
    if(iBegin >= 0) {
      iBegin += sField.length();
      int iEnd = sFilter.indexOf('\'', iBegin);
      if(iEnd > 0 && iEnd > iBegin) {
        return sFilter.substring(iBegin, iEnd).toLowerCase();
      }
    }
    return null;
  }
}