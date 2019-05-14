control "V-62337" do
  title "Wildlfy must be configured to generate log records that show starting
  and ending times for access to the application server management interface."
  desc  "
    Determining when a user has accessed the management interface is important
  to determine the timeline of events when a security incident occurs.
  Generating these events, especially if the management interface is accessed via
  a stateless protocol like HTTP, the log events will be generated when the user
  performs a logon (start) and when the user performs a logoff (end).  Without
  these events, the user and later investigators cannot determine the sequence of
  events and therefore cannot determine what may have happened and by whom it may
  have been done.

      The generation of start and end times within log events allows the user to
  perform their due diligence in the event of a security breach.
    "
  impact 0.5
  tag "gtitle": "SRG-APP-000505-AS-000230"
  tag "gid": "V-62337"
  tag "rid": "SV-76827r1_rule"
  tag "stig_id": "JBOS-AS-000710"
  tag "cci": ["CCI-000172"]
  tag "documentable": false
  tag "nist": ["AU-12 c", "Rev_4"]
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
  tag "fix_id": "F-68257r1_fix"

  connect = attribute('connection')

  describe 'The wildfly server setting: generate log records that show starting and ending times for access to the application server management interface' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
