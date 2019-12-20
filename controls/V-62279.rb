control 'V-62279' do
  title "The Wildfly Server must be configured to use certificates to
  authenticate admins."
  desc  "
    Multifactor authentication creates a layered defense and makes it more
  difficult for an unauthorized person to access the application server.  If one
  factor is compromised or broken, the attacker still has at least one more
  barrier to breach before successfully breaking into the target.  Unlike a
  simple username/password scenario where the attacker could gain access by
  knowing both the username and password without the user knowing his account was
  compromised, multifactor authentication adds the requirement that the attacker
  must have something from the user, such as a token, or to biometrically be the
  user.

      Multifactor authentication is defined as: using two or more factors to
  achieve authentication.

      Factors include:
      (i) something a user knows (e.g., password/PIN);
      (ii) something a user has (e.g., cryptographic identification device,
  token); or
      (iii) something a user is (e.g., biometric). A CAC or PKI Hardware Token
  meets this definition.

      A privileged account is defined as an information system account with
  authorizations of a privileged user.  These accounts would be capable of
  accessing the web management interface.

      When accessing the application server via a network connection,
  administrative access to the application server must be PKI Hardware Token
  enabled or a DoD-approved soft certificate.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000149-AS-000102'
  tag "gid": 'V-62279'
  tag "rid": 'SV-76769r1_rule'
  tag "stig_id": 'JBOS-AS-000265'
  tag "cci": ['CCI-000765']
  tag "documentable": false
  tag "nist": ['IA-2 (1)', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.

  Follow these steps:
  1. Identify the security realm assigned to the management interfaces by using
  the following command:

  For standalone systems:
  \"ls  /core-service=management/management-interface=<INTERFACE-NAME>\"

  For managed domain systems:
  \"ls
  /host=master/core-service=management/management-interface=<INTERFACE-NAME>\"

  Document the name of the security-realm associated with each management
  interface.

  2. Review the security realm using the command:

  For standalone systems:
  \"ls
  /core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication\"

  For managed domains:
  \"ls
  /host=master/core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication\"

  If the command in step 2 does not return a security realm that uses
  certificates for authentication, this is a finding."
  tag "fix": "Configure the application server to authenticate privileged users
  via multifactor/certificate-based authentication mechanisms when using network
  access to the management interface."
  tag "fix_id": 'F-68199r1_fix'

  connect = input('connection')

  mgmt_interfaces = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/management-interface=").stdout.split("\n")

  mgmt_interfaces.each do |interface|

    security_realms = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/security-realm=").stdout.split("\n")
    security_realms.each do |realm|

      get_authentication = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/security-realm=#{realm}/authentication").stdout
      http_enabled = describe command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/management-interface=http-interface") .stdout

      describe.one do
        describe "The wildfly server authentication for security realm #{realm}" do
          subject { get_authentication }
          it { should match /truststore/ }
        end
        describe "The wildfly server authentication for security realm #{realm}" do
          subject { http_enabled }
          it { should  match(%r{console-enabled=false}) }
        end
      end
    end
  end
  if mgmt_interfaces.empty?
    impact 0.0
    describe 'There are no wildfly management realms, therefore this control is not applicable' do
      skip 'There are no wildfly management realms, therefore this control is not applicable'
    end
  end
end
