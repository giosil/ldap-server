# LDAP Server

A lightweight programmable LDAP server.

## Start Server

```
java org.dew.ldap.LDAPServer
```

## Connect
```
host     = localhost
port     = 389
base dn  = ou=users,dc=test
user dn  = uid=admin,dc=test
password = admin
```
![Test on JXplorer](test.png)

## Build

- `git clone https://github.com/giosil/ldap-server.git`
- `mvn clean install`

## Contributors

* [Giorgio Silvestris](https://github.com/giosil)
