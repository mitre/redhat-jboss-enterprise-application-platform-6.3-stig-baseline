control 'V-62231' do
  title "The Wildfly server must generate log records for access and
  authentication events to the management interface."
  desc  "
    Log records can be generated from various components within the Wildfly
  application server.  The minimum list of logged events should be those
  pertaining to access and authentication events to the management interface as
  well as system startup and shutdown events.

      By default, Wildfly does not log management interface access but does provide
  a default file handler.  This handler needs to be enabled.  Configuring this
  setting meets several STIG auditing requirements.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000089-AS-000050'
  tag "gid": 'V-62231'
  tag "rid": 'SV-76721r1_rule'
  tag "stig_id": 'JBOS-AS-000080'
  tag "cci": ['CCI-000169']
  tag "documentable": false
  tag "nist": ['AU-12 a', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly
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

  tag "fix_id": 'F-68151r1_fix'

  connect = input('connection')

  describe 'The Wildfly server generate log records for access and authentication events to the management interface.' do
    subject { command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
