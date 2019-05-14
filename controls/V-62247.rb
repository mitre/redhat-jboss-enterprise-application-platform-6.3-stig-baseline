control 'V-62247' do
  title "The application server must produce log records that contain
sufficient information to establish the outcome of events."
  desc  "
    Information system logging capability is critical for accurate forensic
analysis. Log record content that may be necessary to satisfy the requirement
of this control includes, but is not limited to, time stamps, source and
destination IP addresses, user/process identifiers, event descriptions,
application-specific events, success/fail indications, filenames involved,
access control or flow control rules invoked.

    Success and failure indicators ascertain the outcome of a particular
application server event or function. As such, they also provide a means to
measure the impact of an event and help authorized personnel to determine the
appropriate response.  Event outcome may also include event-specific results
(e.g., the security state of the information system after the event occurred).
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000099-AS-000062'
  tag "gid": 'V-62247'
  tag "rid": 'SV-76737r1_rule'
  tag "stig_id": 'JBOS-AS-000130'
  tag "cci": ['CCI-000134']
  tag "documentable": false
  tag "nist": ['AU-3', 'Rev_4']
  tag "check": "Log on to the OS of the wildfly server with OS permissions that
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
  tag "fix_id": 'F-68167r1_fix'

  connect = attribute('connection')

  describe 'The application server produce log records that contain sufficient information to establish the outcome of events' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=audit/logger=audit-log").stdout }
    it { should_not match(%r{enabled=false}) }
  end
end
