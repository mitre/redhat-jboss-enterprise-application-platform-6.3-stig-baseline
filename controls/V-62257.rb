control 'V-62257' do
  title "Wildfly log records must be off-loaded onto a different system or system
component a minimum of every seven days."
  desc  "
    Wildfly logs by default are written to the local file system.  A centralized
logging solution like syslog should be used whenever possible; however, any log
data stored to the file system needs to be off-loaded.  Wildfly EAP does not
provide an automated backup capability.  Instead, reliance is placed on OS or
third-party tools to back up or off-load the log files.

    Protection of log data includes assuring log data is not accidentally lost
or deleted. Off-loading log records to a different system or onto separate
media from the system the application server is actually running on helps to
assure that, in the event of a catastrophic system failure, the log records
will be retained.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000125-AS-000084'
  tag "gid": 'V-62257'
  tag "rid": 'SV-76747r1_rule'
  tag "stig_id": 'JBOS-AS-000195'
  tag "cci": ['CCI-001348']
  tag "documentable": false
  tag "nist": ['AU-9 (2)', 'Rev_4']
  tag "check": "Interview the system admin and obtain details on how the log
files are being off-loaded to a different system or media.

If the log files are not off-loaded a minimum of every 7 days, this is a
finding."
  tag "fix": "Configure the application server to off-load log records every
seven days onto a different system or media from the system being logged."
  tag "fix_id": 'F-68177r1_fix'

  connect = attribute('connection')
  describe "The wildfly syslog-handler configuration" do
    subject { command("/bin/sh #{ attribute('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /subsystem=logging/syslog-handler=").stdout }
    it { should_not eq '' }
  end
end
