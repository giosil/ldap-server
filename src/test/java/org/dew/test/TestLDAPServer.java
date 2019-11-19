package org.dew.test;

import org.dew.ldap.*;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class TestLDAPServer extends TestCase {
	
	public TestLDAPServer(String testName) {
		super(testName);
	}
	
	public static Test suite() {
		return new TestSuite(TestLDAPServer.class);
	}
	
	public void testApp() {
		System.out.println("LDAPServer ver. " + LDAPServer.sVERSION);
		System.out.println("host     = localhost");
		System.out.println("port     = 389");
		System.out.println("base dn  = ou=users,dc=test");
		System.out.println("user dn  = uid=admin,dc=test");
		System.out.println("password = admin");
	}
	
}
