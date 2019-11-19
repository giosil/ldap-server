package org.dew.ldap;

import java.util.*;

public 
class LDAPMessage 
{
	private int id;
	private int protocolOp;
	private List<Object> controls = new ArrayList<Object>();
	
	public LDAPMessage()
	{
	}
	
	public LDAPMessage(int id, int protocolOp)
	{
		this.id = id;
		this.protocolOp = protocolOp;
	}
	
	public LDAPMessage(int id, int protocolOp, List<Object> controls)
	{
		this.id = id;
		this.protocolOp = protocolOp;
		if(controls != null) {
			this.controls = controls;
		}
	}
	
	public int getId() {
		return id;
	}
	
	public void setId(int id) {
		this.id = id;
	}
	
	public int getProtocolOp() {
		return protocolOp;
	}
	
	public void setProtocolOp(int protocolOp) {
		this.protocolOp = protocolOp;
	}
	
	public List<Object> getControls() {
		return controls;
	}
	
	public void setControls(List<Object> controls) {
		if(controls == null) {
			this.controls.clear();
		}
		this.controls = controls;
	}
	
	public String getStringControl(int iIndex) {
		if(controls == null) return null;
		if(controls.size() > iIndex) {
			Object oValue = controls.get(iIndex);
			if(oValue == null) return null;
			return oValue.toString();
		}
		return null;
	}
	
	public int getIntControl(int iIndex) {
		if(controls == null) return 0;
		if(controls.size() > iIndex) {
			Object oValue = controls.get(iIndex);
			if(oValue instanceof Number) {
				return ((Number) oValue).intValue();
			}
			return 0;
		}
		return 0;
	}
	
	@SuppressWarnings("unchecked")
	public List<Object> getListControl(int iIndex) {
		if(controls == null) return new ArrayList<Object>();
		if(controls.size() > iIndex) {
			Object oValue = controls.get(iIndex);
			if(oValue instanceof List) {
				return (List<Object>) oValue;
			}
			return new ArrayList<Object>();
		}
		return new ArrayList<Object>();
	}
	
	public String getLastStringControl(int iOffset) {
		if(controls == null) return null;
		if(controls.size() > iOffset) {
			Object oValue = controls.get(controls.size() - 1 - iOffset);
			if(oValue == null) return null;
			return oValue.toString();
		}
		return null;
	}
	
	public int getLastIntControl(int iOffset) {
		if(controls == null) return 0;
		if(controls.size() > iOffset) {
			Object oValue = controls.get(controls.size() - 1 - iOffset);
			if(oValue instanceof Number) {
				return ((Number) oValue).intValue();
			}
			return 0;
		}
		return 0;
	}
	
	@SuppressWarnings("unchecked")
	public List<Object> getLastListControl(int iOffset) {
		if(controls == null) return new ArrayList<Object>();
		if(controls.size() > iOffset) {
			Object oValue = controls.get(controls.size() - 1 - iOffset);
			if(oValue instanceof List) {
				return (List<Object>) oValue;
			}
			return new ArrayList<Object>();
		}
		return new ArrayList<Object>();
	}
	
	public int hashCode() {
		return id;
	}
	
	public String toString() {
		String sResult = "";
		sResult += id + ", ";
		switch (protocolOp) {
			case ILDAPConstants.LDAP_REQ_BIND:    sResult += "bind, ";    break;
			case ILDAPConstants.LDAP_REQ_UNBIND:  sResult += "unbind, ";  break;
			case ILDAPConstants.LDAP_REQ_SEARCH:  sResult += "search, ";  break;
			case ILDAPConstants.LDAP_REQ_MODIFY:  sResult += "modify, ";  break;
			case ILDAPConstants.LDAP_REQ_ADD:     sResult += "add, ";     break;
			case ILDAPConstants.LDAP_REQ_DELETE:  sResult += "delete, ";  break;
			case ILDAPConstants.LDAP_REQ_MODRDN:  sResult += "modrdn, ";  break;
			case ILDAPConstants.LDAP_REQ_COMPARE: sResult += "compare, "; break;
			case ILDAPConstants.LDAP_REQ_ABANDON: sResult += "abandon, "; break;
			default: sResult += protocolOp + ", "; break;
		}
		if(protocolOp != ILDAPConstants.LDAP_REQ_BIND) {
			sResult += controls;
		}
		else {
			// Nel caso di bind si maschera l'ultimo elementro di controls che corrisponde alla password.
			String sControls = null;
			if(controls != null) {
				sControls = "";
				for(int i = 0; i < controls.size() - 1; i++) {
					sControls += controls.get(i) + ", ";
				}
				if(sControls.length() > 0 && controls.size() > 0) sControls += "*";
				sControls = "[" + sControls + "]";
			}
			else {
				sControls = "[]";
			}
			sResult += sControls;
		}
		return sResult;
	}
}
