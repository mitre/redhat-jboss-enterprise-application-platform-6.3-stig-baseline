control "V-62285" do
  title "Wildfly management Interfaces must be integrated with a centralized
  authentication mechanism that is configured to manage accounts according to DoD
  policy."
  desc  "
    Wildfly EAP provides a security realm called ManagementRealm.  By default,
  this realm uses the mgmt-users.properties file for authentication.  Using
  file-based authentication does not allow the Wildfly server to be in compliance
  with a wide range of user management requirements such as automatic disabling
  of inactive accounts as per DoD policy.  To address this issue, the management
  interfaces used to manage the JBoss server must be associated with a security
  realm that provides centralized authentication management.  Examples are AD or
  LDAP.

      Management of user identifiers is not applicable to shared information
  system accounts (e.g., guest and anonymous accounts). It is commonly the case
  that a user account is the name of an information system account associated
  with an individual.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000163-AS-000111"
  tag "gid": "V-62285"
  tag "rid": "SV-76775r1_rule"
  tag "stig_id": "JBOS-AS-000290"
  tag "cci": ["CCI-000795"]
  tag "documentable": false
  tag "nist": ["IA-4 e", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script.
  Connect to the server and authenticate.

  The $JBOSS_HOME default is /opt/bin/widfly

  Obtain the list of management interfaces by running the command:
  \"ls /core-service=management/management-interface\"

  Identify the security realm used by each management interface configuration by
  running the command:
  \"ls /core-service=management/management-interface=<MANAGEMENT-INTERFACE-NAME>\"

  Determine if the security realm assigned to the management interface uses LDAP
  for authentication by running the command:
  \"ls
  /core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication\"

  If  the security realm assigned to the management interface does not utilize
  LDAP for authentication, this is a finding."
  tag "fix": "Follow steps in section 11.8 - Management Interface Security in
  the
  Wildfly-Administration_and_Configuration_Guide-en-US
  document.

  1. Create an outbound connection to the LDAP server.
  2. Create an LDAP-enabled security realm.
  3. Reference the new security domain in the Management Interface."
  tag "fix_id": "F-68205r1_fix"

  ldap = attribute('ldap')
  connect = attribute('connection')

  management_interfaces = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/management-interface=").stdout.split("\n")

  management_interfaces.each do |interface|

    security_realms = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/security-realm=").stdout.split("\n")
     security_realms.each do |realm|
      describe "The security realm #{realm} authentication mechanism" do
        subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect}  --commands=ls\\ /core-service=management/security-realm=#{realm}/authentication").stdout }
        it { should match /ldap/}
      end
    end
  end
  if management_interfaces.empty?
    impact 0.0
    describe 'The are no Wildfly accounts with the following roles: auditor, administrator, superuser, deployer, maintainer, monitor, or operator, therefore this control is not applicable' do
      skip 'The are no Wildfly accounts with the following roles: auditor, administrator, superuser, deployer, maintainer, monitor, or operator, therefore this control is not applicable'
    end
  end
end
