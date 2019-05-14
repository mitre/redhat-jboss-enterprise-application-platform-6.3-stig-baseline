control 'V-62291' do
  title "LDAP enabled security realm value allow-empty-passwords must be set to
  false."
  desc  "
    Passwords need to be protected at all times, and encryption is the standard
  method for protecting passwords during transmission.  If passwords are not
  encrypted, they can be plainly read (i.e., clear text) and easily compromised.

      Application servers have the capability to utilize either certificates
  (tokens) or user IDs and passwords in order to authenticate. When the
  application server transmits or receives passwords, the passwords must be
  encrypted.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000172-AS-000120'
  tag "gid": 'V-62291'
  tag "rid": 'SV-76781r1_rule'
  tag "stig_id": 'JBOS-AS-000305'
  tag "cci": ['CCI-000197']
  tag "documentable": false
  tag "nist": ['IA-5 (1) (c)', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.
  Run the command:

  \"ls
  /core-service=management/security-realm=ldap_security_realm/authentication=ldap\"

  If \"allow-empty-passwords=true\", this is a finding."
  tag "fix": "Configure the LDAP Security Realm using default settings that
  sets \"allow-empty-values\" to false.  LDAP Security Realm creation is
  described in section 11.9 -Add an LDAP Security Realm in the
  JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US
  document."
  tag "fix_id": 'F-68211r1_fix'

  connect = attribute('connection')
  ldap = attribute('ldap')

  if ldap
    describe 'The LDAP enabled security realm value allow-empty-passwords' do
      subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/security-realm=ldap_security_realm/authentication=ldap").stdout }
      it { should_not match(%r{allow-empty-passwords=true}) }
    end
  else
    describe 'Ldap is not being used, control not applicable' do
      skip 'Ldap is not being used, control not applicable'
    end
  end
end
