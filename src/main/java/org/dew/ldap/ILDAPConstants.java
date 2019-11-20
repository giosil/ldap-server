package org.dew.ldap;

public 
interface ILDAPConstants 
{
  // general
  public static final int LDAP_PORT = 389;
  public static final int LDAP_VERSION = 3;
  public static final int LDAP_MAX_ATTR_LEN = 100;

  // request
  public static final int LDAP_REQ_BIND = 0x60;
  public static final int LDAP_REQ_UNBIND = 0x42;
  public static final int LDAP_REQ_SEARCH = 0x63;
  public static final int LDAP_REQ_MODIFY = 0x66;
  public static final int LDAP_REQ_ADD = 0x68;
  public static final int LDAP_REQ_DELETE = 0x4a;
  public static final int LDAP_REQ_MODRDN = 0x6c;
  public static final int LDAP_REQ_COMPARE = 0x6e;
  public static final int LDAP_REQ_ABANDON = 0x50;

  // response
  public static final int LDAP_RES_BIND = 0x61;
  public static final int LDAP_RES_SEARCH = 0x45;       //new one for NUTSCAPE
  public static final int LDAP_RES_SEARCH_ENTRY = 0x64;
  public static final int LDAP_RES_SEARCH_RESULT = 0x65;
  public static final int LDAP_RES_MODIFY = 0x67;
  public static final int LDAP_RES_ADD = 0x69;
  public static final int LDAP_RES_DELETE = 0x6b;
  public static final int LDAP_RES_MODRDN = 0x6d;
  public static final int LDAP_RES_COMPARE = 0x6f;

  // authentication method
  public static final int LDAP_AUTH_NONE = 0x00;
  public static final int LDAP_AUTH_SIMPLE = 0x80;    // context specific

  // filter types
  public static final int LDAP_FILTER_AND = 0xa0;
  public static final int LDAP_FILTER_OR = 0xa1;
  public static final int LDAP_FILTER_NOT = 0xa2;
  public static final int LDAP_FILTER_EQUALITY = 0xa3;
  public static final int LDAP_FILTER_SUBSTRINGS = 0xa4;
  public static final int LDAP_FILTER_GE = 0xa5;
  public static final int LDAP_FILTER_LE = 0xa6;
  public static final int LDAP_FILTER_PRESENT = 0x87;
  public static final int LDAP_FILTER_APPROX = 0xa8;
  public static final int LDAP_FILTER_SUBSTR_SEQ = 0x30;

  // substring filter component types
  public static final int LDAP_SUBSTRING_INITIAL = 0x80;
  public static final int LDAP_SUBSTRING_ANY = 0x81;
  public static final int LDAP_SUBSTRING_FINAL = 0x82;

  // search scopes
  public static final int LDAP_SCOPE_BASE = 0x00;
  public static final int LDAP_SCOPE_ONELEVEL = 0x01;
  public static final int LDAP_SCOPE_SUBTREE = 0x02;

  // modifying operations
  public static final int LDAP_MOD_ADD = 0x00;
  public static final int LDAP_MOD_DELETE = 0x01;
  public static final int LDAP_MOD_REPLACE = 0x02;
  public static final int LDAP_MOD_BVALUES = 0x80;

  // aliase handler
  public static final int LDAP_DEREF_NEVER = 0x00;
  public static final int LDAP_DEREF_SEARCHING = 0x01;
  public static final int LDAP_DEREF_FINDING = 0x02;
  public static final int LDAP_DEREF_ALWAYS = 0x03;

  // error codes
  public static final int LDAP_SUCCESS = 0x00;
  public static final int LDAP_OPERATIONS_ERROR = 0x01;
  public static final int LDAP_PROTOCOL_ERROR = 0x02;
  public static final int LDAP_TIMELIMIT_EXCEEDED = 0x03;
  public static final int LDAP_SIZELIMIT_EXCEEDED = 0x04;
  public static final int LDAP_COMPARE_FALSE = 0x05;
  public static final int LDAP_COMPARE_TRUE = 0x06;
  public static final int LDAP_PARTIAL_RESULTS = 0x09;
  public static final int LDAP_NO_SUCH_ATTRIBUTE = 0x10;
  public static final int LDAP_UNDEFINED_TYPE = 0x11;
  public static final int LDAP_TYPE_OR_VALUE_EXISTS = 0x14;
  public static final int LDAP_INVALID_SYNTAX = 0x15;
  public static final int LDAP_NO_SUCH_OBJECT = 0x20;
  public static final int LDAP_INVALID_DN_SYNTAX = 0x22;
  public static final int LDAP_IS_LEAF = 0x23;
  public static final int LDAP_INVALID_CREDENTIALS = 0x31;
  public static final int LDAP_BUSY = 0x33;
  public static final int LDAP_UNAVAILABLE = 0x34;
  public static final int LDAP_UNWILLING_TO_PERFORM = 0x35;
  public static final int LDAP_OBJECT_CLASS_VIOLATION = 0x41;
  public static final int LDAP_NOT_ALLOWED_ON_NONLEAF = 0x42;
  public static final int LDAP_NOT_ALLOWED_ON_RDN = 0x43;
  public static final int LDAP_ALREADY_EXISTS = 0x44;
  public static final int LDAP_SERVER_DOWN = 0x51;

  // Ber coding system
  public static final int LBER_CLASS_UNIVERSAL = 0x00;
  public static final int LBER_CLASS_APPLICATION = 0x40;
  public static final int LBER_CLASS_CONTEXT = 0x80;
  public static final int LBER_CLASS_PRIVATE = 0xc0;

  public static final int LBER_PRIMITIVE = 0x00;
  public static final int LBER_CONSTRUCTED = 0x20;

  public static final int LBER_LENGTH = 0x00;
  public static final int LBER_BOOLEAN = 0x01;
  public static final int LBER_INTEGER = 0x02;
  public static final int LBER_BITSTRING = 0x03;
  public static final int LBER_OCTETSTRING = 0x04;
  public static final int LBER_NULL = 0x05;
  public static final int LBER_ENUMERATED = 0x0a;
  public static final int LBER_SEQUENCE = 0x30;
  public static final int LBER_SET = 0x31;

  public static final int LBER_DEFAULT = 0xffffffff;
  public static final int LBER_USE_DER = 0x01;
}
