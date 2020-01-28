control 'V-62329' do
  title "Wildfly must be configured to generate log records when
  successful/unsuccessful attempts to modify privileges occur."
  desc  "Changing privileges of a subject/object may cause a subject/object to
  gain or lose capabilities.  When successful/unsuccessful changes are made, the
  event needs to be logged.  By logging the event, the modification or attempted
  modification can be investigated to determine if it was performed inadvertently
  or maliciously."
  impact 0.5
  tag "gtitle": 'SRG-APP-000495-AS-000220'
  tag "gid": 'V-62329'
  tag "rid": 'SV-76819r1_rule'
  tag "stig_id": 'JBOS-AS-000690'
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
  tag "fix_id": 'F-68249r1_fix'

  connect = input('connection')

  describe 'The wildfly setting: generate log records when successful/unsuccessful attempts to modify privileges occur' do
    subject { command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
