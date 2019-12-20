control 'V-62339' do
  title "Wildfly must be configured to generate log records when concurrent
  logons from different workstations occur to the application server management
  interface."
  desc  "
    Concurrent logons from different systems could possibly indicate a
  compromised account.  When concurrent logons are made from different
  workstations to the management interface, a log record needs to be generated.
  This configuration setting provides forensic evidence that allows the system
  administrator to investigate access to the system and determine if the
  duplicate access was authorized or not.

      Wildfly provides a multitude of different log formats, and API calls that log
  access to the system.  If the default format and location is not used, the
  system admin must provide the configuration documentation and settings that
  show that this requirement is being met.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000506-AS-000231'
  tag "gid": 'V-62339'
  tag "rid": 'SV-76829r1_rule'
  tag "stig_id": 'JBOS-AS-000715'
  tag "cci": ['CCI-000172']
  tag "documentable": false
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.

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
  tag "fix_id": 'F-68259r1_fix'

  connect = input('connection')

  describe 'The wildfly server setting: generate log records when concurrent
  logons from different workstations occur to the application server management interface' do
    subject { command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
