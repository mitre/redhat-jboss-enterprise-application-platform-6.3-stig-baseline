control 'V-62299' do
  title "Wildfly file permissions must be configured to protect the
  confidentiality and integrity of application files."
  desc  "
    The Wildfly EAP Application Server is a Java-based AS.  It is installed on
  the OS file system and depends upon file system access controls to protect
  application data at rest.  The file permissions set on the Wildfly EAP home
  folder must be configured so as to limit access to only authorized people and
  processes.  The account used for operating the Wildfly server and any designated
  administrative or operational accounts are the only accounts that should have
  access.

      When data is written to digital media such as hard drives, mobile
  computers, external/removable hard drives, personal digital assistants,
  flash/thumb drives, etc., there is risk of data loss and data compromise.
  Steps must be taken to ensure data stored on the device is protected.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000231-AS-000133'
  tag "gid": 'V-62299'
  tag "rid": 'SV-76789r1_rule'
  tag "stig_id": 'JBOS-AS-000400'
  tag "cci": ['CCI-001199']
  tag "documentable": false
  tag "nist": ['SC-28', 'Rev_4']
  tag "check": "By default, Wildfly installs its files into a folder called
  \"wildfly\".   This folder by default is stored within the home folder of
  the Wildfly user account.  The installation process, however, allows for the
  override of default values to obtain folder and user account information from
  the system admin.

  Log on with a user account with Wildfly access and permissions.

  Navigate to the \"Wildfly\" folder using the relevant OS commands for
  either a UNIX-like OS or a Windows OS.

  Examine the permissions of the Wildfly folder.

  Owner can be full access.
  Group can be full access.
  All others must be restricted to execute access or no permission.

  If the Wildfly folder is world readable or world writable, this is a finding."
  tag "fix": "Configure file permissions on the Wildfly folder to protect from
  unauthorized access."
  tag "fix_id": 'F-68219r1_fix'
  describe directory("#{ attribute('jboss_home') }/") do
    it { should_not be_readable.by('others') }
  end
  describe directory("#{ attribute('jboss_home') }/") do
    it { should_not be_writable.by('others') }
  end
end
