control 'V-62277' do
  title "The Wildfly Server must be configured to utilize a centralized
  authentication mechanism such as AD or LDAP."
  desc  "
    To assure accountability and prevent unauthorized access, application
  server users must be uniquely identified and authenticated.  This is typically
  accomplished via the use of a user store that is either local (OS-based) or
  centralized (Active Directory/LDAP) in nature.  It should be noted that Wildfly
  does not specifically mention Active Directory since AD is LDAP aware.

      To ensure accountability and prevent unauthorized access, the JBoss Server
  must be configured to utilize a centralized authentication mechanism.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000148-AS-000101'
  tag "gid": 'V-62277'
  tag "rid": 'SV-76767r1_rule'
  tag "stig_id": 'JBOS-AS-000260'
  tag "cci": ['CCI-000764']
  tag "documentable": false
  tag "nist": ['IA-2', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly
  Run the jboss-cli script.
  Connect to the server and authenticate.

  To obtain the list of security realms run the command:
  \"ls /core-service=management/security-realm=\"

  Review each security realm using the command:
  \"ls
  /core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication\"

  If this command does not return a security realm that uses LDAP for
  authentication, this is a finding."
  tag "fix": "Follow steps in section 11.8 - Management Interface Security in
  the
  Wildfly_Enterprise_Application_Administration_and_Configuration_Guide-en-US
  document.

  1. Create an outbound connection to the LDAP server.
  2. Create an LDAP-enabled security realm.
  3. Reference the new security domain in the Management Interface."
  tag "fix_id": 'F-68197r1_fix'

  connect = attribute('connection')

  get_security_realms = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/security-realm=").stdout.split("\n")

  get_security_realms.each do |security_realm|
    describe "The security realm #{security_realm} authentication mechanism" do
      subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/security-realm=#{security_realm}/authentication").stdout }
      it { should include 'ldap' }
    end
  end
  if get_security_realms.empty?
    impact 0.0
    describe 'There are no wildfly security realms configured, therefore this controls is not applicable' do
      skip 'There are no wildfly security realms configured, therefore this controls is not applicable'
    end
  end
end
