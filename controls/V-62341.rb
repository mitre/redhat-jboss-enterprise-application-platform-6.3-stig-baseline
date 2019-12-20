control 'V-62341' do
  title "Wildlfy must be configured to generate log records for all account
  creations, modifications, disabling, and termination events."
  desc  "
    The maintenance of user accounts is a key activity within the system to
  determine access and privileges.  Through changes to accounts, an attacker can
  create an account for persistent access, modify an account to elevate
  privileges, or terminate/disable an account(s) to cause a DoS for user(s).  To
  be able to track and investigate these actions, log records must be generated
  for any account modification functions.

      Application servers either provide a local user store, or they can
  integrate with enterprise user stores like LDAP.  As such, the application
  server must be able to generate log records on account creation, modification,
  disabling, and termination.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000509-AS-000234'
  tag "gid": 'V-62341'
  tag "rid": 'SV-76831r1_rule'
  tag "stig_id": 'JBOS-AS-000720'
  tag "cci": ['CCI-000172']
  tag "documentable": false
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "check": "Log on to the OS of the Wildlfy server with OS permissions that
  allow access to Wildlfy.

  The $JBOSS_HOME default is /opt/bin/widfly

  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script to start the Command Line Interface (CLI).
  Connect to the server and authenticate.
  Run the command:

  For a Managed Domain configuration:
  \"ls
  host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\"

  For a Standalone configuration:
  \"ls
  /core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\"

  If \"enabled\" = false, this is a finding."
  tag "fix": "Launch the jboss-cli management interface.
  Connect to the server by typing \"connect\", authenticate as a user in the
  Superuser role, and run the following command:

  For a Managed Domain configuration:
  \"host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\"

  For a Standalone configuration:
  \"/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)\""
  tag "fix_id": 'F-68261r1_fix'

  connect = input('connection')

  describe 'The wildfly server setting: generate log records for all account creations, modifications, disabling, and termination events' do
    subject { command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
