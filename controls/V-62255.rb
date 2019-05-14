control 'V-62255' do
  title "File permissions must be configured to protect log information from
unauthorized deletion."
  desc  "
    If log data were to become compromised, then competent forensic analysis
and discovery of the true source of potentially malicious system activity is
difficult, if not impossible, to achieve.

    When not configured to use a centralized logging solution like a syslog
server, the Wildfly EAP application server writes log data to log files that are
stored on the OS, appropriate file permissions must be used to restrict
deletion.

    Logon formation includes all information (e.g., log records, log settings,
transaction logs, and log reports) needed to successfully log information
system activity. Application servers must protect log information from
unauthorized deletion.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000120-AS-000080'
  tag "gid": 'V-62255'
  tag "rid": 'SV-76745r1_rule'
  tag "stig_id": 'JBOS-AS-000175'
  tag "cci": ['CCI-000164']
  tag "documentable": false
  tag "nist": ['AU-9', 'Rev_4']
  tag "check": "Examine the log file locations and inspect the file
permissions.  Interview the system admin to determine log file locations. The
default location for the log files is:

Standalone configuration:
$JBOSS_HOME;/standalone/log/

Managed Domain configuration:
$JBOSS_HOME;/domain/servers/<servername>/log/
$JBOSS_HOME;/domain/log/

Review the file permissions for the log file directories.  The method used for
identifying file permissions will be based upon the OS the EAP server is
installed on.

Identify all users with file permissions that allow them to delete log files.

Request documentation from system admin that identifies the users who are
authorized to delete log files.

If unauthorized users are allowed to delete log files, or if documentation that
identifies the users who are authorized to delete log files is missing, this is
a finding."
  tag "fix": "Configure the OS file permissions on the application server to
protect log information from unauthorized deletion."
  tag "fix_id": 'F-68175r1_fix'

  wildfly_group = attribute('wildfly_group')
  wildly_owner = attribute('wildly_owner')
  describe directory("/opt/wildfly/standalone/log") do
    its('owner') { should eq "#{wildly_owner}" }
    its('group') { should eq "#{wildfly_group}" }
    its('mode') { should cmp '0750' }
  end
end
