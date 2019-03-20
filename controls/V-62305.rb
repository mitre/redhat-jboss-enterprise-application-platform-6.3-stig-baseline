CONNECT= attribute(
  'connection',
  description: 'Minimum Web vendor-supported version.',
  default: ''
)

control "V-62305" do
  title "The application server must prevent non-privileged users from
  executing privileged functions to include disabling, circumventing, or altering
  implemented security safeguards/countermeasures."
  desc  "
    Preventing non-privileged users from executing privileged functions
  mitigates the risk that unauthorized individuals or processes may gain
  unnecessary access to information or privileges.

      Restricting non-privileged users also prevents an attacker who has gained
  access to a non-privileged account, from elevating privileges, creating
  accounts, and performing system checks and maintenance.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000340-AS-000185"
  tag "gid": "V-62305"
  tag "rid": "SV-76795r1_rule"
  tag "stig_id": "JBOS-AS-000475"
  tag "cci": ["CCI-002235"]
  tag "documentable": false
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script.
  Connect to the server and authenticate.

  Run the following command:

  For standalone servers:
  \"ls /core-service=management/access=authorization/\"

  For managed domain installations:
  \"ls /host=master/core-service=management/access=authorization/\"

  If the \"provider\" attribute is not set to \"rbac\", this is a finding."
  tag "fix": "Run the following command.
  $JBOSS_HOME;/bin/jboss-cli.sh -c -> connect -> cd
  /core-service=management/access-authorization :write-attribute(name=provider,
  value=rbac)

  Restart Wildfly.

  Map users to roles by running the following command.  Upper-case words are
  variables.

  role-mapping=ROLENAME/include=ALIAS:add(name-USERNAME, type=USER ROLE)"
  tag "fix_id": "F-68225r1_fix"
  describe "The wildfly application server's access authorization" do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/access=authorization/").stdout }
    it { should match(%r{provider=rbac}) }
  end 
end

