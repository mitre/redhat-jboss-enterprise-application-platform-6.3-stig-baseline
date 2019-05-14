control 'V-62309' do
  title "The Wildfly server must be configured to utilize syslog logging."
  desc  "
    Information system logging capability is critical for accurate forensic
  analysis. Log record content that may be necessary to satisfy the requirement
  of this control includes, but is not limited to, time stamps, source and
  destination IP addresses, user/process identifiers, event descriptions,
  application-specific events, success/fail indications, filenames involved,
  access control or flow control rules invoked.

      Off-loading is a common process in information systems with limited log
  storage capacity.

      Centralized management of log records provides for efficiency in
  maintenance and management of records, as well as the backup and archiving of
  those records. Application servers and their related components are required to
  off-load log records onto a different system or media than the system being
  logged.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000358-AS-000064'
  tag "gid": 'V-62309'
  tag "rid": 'SV-76799r1_rule'
  tag "stig_id": 'JBOS-AS-000505'
  tag "cci": ['CCI-001851']
  tag "documentable": false
  tag "nist": ['AU-4 (1)', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.

  The $JBOSS_HOME default is /opt/bin/widfly

  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script.
  Connect to the server and authenticate.
  Run the command:

  Standalone configuration:
  \"ls /subsystem=logging/syslog-handler=\"

  Domain configuration:
  \"ls /profile=<specify>/subsystem=logging/syslog-handler=\"
  Where <specify> = the selected application server profile of; default,full,
  full-ha or ha.

  If no values are returned, this is a finding."
  tag "fix": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script.
  Connect to the server and authenticate.
  Run the command:

  Standalone configuration:
  \"ls /subsystem=logging/syslog-handler=\"

  Domain configuration:
  \"ls /profile=default/subsystem=logging/syslog-handler=\"

  If no values are returned, this is a finding."
  tag "fix_id": 'F-68229r1_fix'

  connect = attribute('connection')

  describe 'The wildfly server syslog handler' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /subsystem=logging/syslog-handler=").stdout }
    it { should_not eq '' }
  end
end
