control 'V-62293' do
  title "Wildfly must utilize encryption when using LDAP for authentication."
  desc  "
    Passwords need to be protected at all times, and encryption is the standard
  method for protecting passwords during transmission.

    Application servers have the capability to utilize LDAP directories for
  authentication. If LDAP connections are not protected during transmission,
  sensitive authentication credentials can be stolen. When the application server
  utilizes LDAP, the LDAP traffic must be encrypted.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000172-AS-000121'
  tag "gid": 'V-62293'
  tag "rid": 'SV-76783r1_rule'
  tag "stig_id": 'JBOS-AS-000310'
  tag "cci": ['CCI-000197']
  tag "documentable": false
  tag "nist": ['IA-5 (1) (c)', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.

  Run the following command:

  For standalone servers:
  \"ls
  /socket-binding-group=standard-sockets/remote-destination-outbound-socket-binding=ldap_connection\"

  For managed domain installations:
  \"ls
  /socket-binding-group=<PROFILE>/remote-destination-outbound-socket-binding=\"

  The default port for secure LDAP is 636.

  If 636 or secure LDAP protocol is not utilized, this is a finding."
  tag "fix": "Follow steps in section 11.8 - Management Interface Security in
  the
  JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US
  document.

  1. Create an outbound connection to the LDAP server.
  2. Create an LDAP-enabled security realm.
  3. Reference the new security domain in the Management Interface."
  tag "fix_id": 'F-68213r1_fix'

  connect = attribute('connection')
  ldap = attribute('ldap')

  if ldap
    describe 'A manual review is required to ensure wildfly uses encryption when using LDAP for authentication' do
      skip 'A manual review is required to ensure wildfly uses encryption when using LDAP for authentication'
    end
  else
    describe command("/bin/sh #{ attribute('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /subsystem=undertow/server=default-server/https-listener=https") do
      its('stdout') { should match(%r{enabled=true}) }
    end
  end
end
