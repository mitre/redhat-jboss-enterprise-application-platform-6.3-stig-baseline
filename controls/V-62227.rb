control 'V-62227' do
  title "The Wildfly server must be configured with Role Based Access Controls."
  desc  "By default, the Wildfly server is not configured to utilize role based
access controls (RBAC).  RBAC provides the capability to restrict user access
to their designated management role, thereby limiting access to only the Wildfly
functionality that they are supposed to have.  Without RBAC, the Wildfly server
is not able to enforce authorized access according to role."
  impact 0.7
  tag "gtitle": 'SRG-APP-000033-AS-000024'
  tag "gid": 'V-62227'
  tag "rid": 'SV-76717r1_rule'
  tag "stig_id": 'JBOS-AS-000035'
  tag "cci": ['CCI-000213']
  tag "documentable": false
  tag "nist": ['AC-3', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
allow access to Wildfly.
Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

The $JBOSS_HOME default is /opt/bin/widfly
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

Map users to roles by running the following command.  Upper-case words  are
variables.

role-mapping=ROLENAME/include=ALIAS:add(name-USERNAME, type=USER ROLE)"
  tag "fix_id": 'F-68147r1_fix'

  connect = attribute('connection')

  describe 'The wildfly server authorization access' do
    subject { command("/bin/sh #{ attribute('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/").stdout }
    it { should match(%r{provider=rbac}) }
  end
end
