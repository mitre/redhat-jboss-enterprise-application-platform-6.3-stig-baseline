control 'V-62243' do
  title "Wildfly must be configured to produce log records that establish which
hosted application triggered the events."
  desc  "
    Application server logging capability is critical for accurate forensic
analysis.  Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    By default, no web logging is enabled in Wildfly.  Logging can be configured
per web application or by virtual server.  If web application logging is not
set up, application activity will not be logged.

    Ascertaining the correct location or process within the application server
where the events occurred is important during forensic analysis.  To determine
where an event occurred, the log data must contain data containing the
application identity.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000097-AS-000060'
  tag "gid": 'V-62243'
  tag "rid": 'SV-76733r1_rule'
  tag "stig_id": 'JBOS-AS-000120'
  tag "cci": ['CCI-000132']
  tag "documentable": false
  tag "nist": ['AU-3', 'Rev_4']
  tag "check": "Application logs are a configurable variable.  Interview the
system admin, and have them identify the applications that are running on the
application server.  Have the system admin identify the log files/location
where application activity is stored.

Review the log files to ensure each application is uniquely identified within
the logs or each application has its own unique log file.

Generate application activity by either authenticating to the application or
generating an auditable event, and ensure the application activity is recorded
in the log file.  Recently time stamped application events are suitable
evidence of compliance.

If the log records do not indicate which application hosted on the application
server generated the event, or if no events are recorded related to application
activity, this is a finding."
  tag "fix": "Configure log formatter to audit application activity so
individual application activity can be identified."
  tag "fix_id": 'F-68163r1_fix'
  file = command('find / -name "log4j.properties" 2>/dev/null | grep -v example').stdout

  describe 'The number of log4j.properties files found' do
    subject { command('find / -name "log4j.properties" 2>/dev/null | grep -v example | wc -l').stdout }
    it { should_not match /0/ }
  end

  describe 'The number of words in the log4j.properties file' do
    subject { command("wc -c #{file}").stdout }
    it { should_not match /0/ }
  end
end
