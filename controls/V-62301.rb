control 'V-62301' do
  title "Access to Wildfly log files must be restricted to authorized users."
  desc  "
    If the application provides too much information in error logs and
  administrative messages to the screen, this could lead to compromise. The
  structure and content of error messages need to be carefully considered by the
  organization and development team. The extent to which the information system
  is able to identify and handle error conditions is guided by organizational
  policy and operational requirements.

      Application servers must protect the error messages that are created by the
  application server. All application server users' accounts are used for the
  management of the server and the applications residing on the application
  server. All accounts are assigned to a certain role with corresponding access
  rights. The application server must restrict access to error messages so only
  authorized users may view them. Error messages are usually written to logs
  contained on the file system. The application server will usually create new
  log files as needed and must take steps to ensure that the proper file
  permissions are utilized when the log files are created.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000267-AS-000170'
  tag "gid": 'V-62301'
  tag "rid": 'SV-76791r1_rule'
  tag "stig_id": 'JBOS-AS-000425'
  tag "cci": ['CCI-001314']
  tag "documentable": false
  tag "nist": ['SI-11 b', 'Rev_4']
  tag "check": "If the Wildfly log folder is installed in the default location
  and AS-000133-JBOSS-00079 is not a finding, the log folders are protected and
  this requirement is not a finding.

  By default, Wildlfy installs its log files into a sub-folder of the
  \"Wildfly\" home folder.
  Using a UNIX like OS example, the default location for log files is:

  The $JBOSS_HOME default is /opt/bin/widfly

  JBOSS_HOME/standalone/log
  JBOSS_HOME/domain/log

  For a standalone configuration:
  JBOSS_HOME/standalone/log/server.log\"  Contains all server log messages,
  including server startup messages.

  For a domain configuration:
  JBOSS_HOME/domain/log/hostcontroller.log
  Host Controller boot log. Contains log messages related to the startup of the
  host controller.

  JBOSS_HOME/domain/log/processcontroller.log
  Process controller boot log. Contains log messages related to the startup of
  the process controller.

  JBOSS_HOME/domain/servers/SERVERNAME/log/server.log
  The server log for the named server. Contains all log messages for that server,
  including server startup messages.

  Log on with an OS user account with Wildfly access and permissions.

  Navigate to the \"Wildfly\" folder using the relevant OS commands for
  either a UNIX like OS or a Windows OS.

  Examine the permissions of the Wildfly logs folders.

  Owner can be full access.
  Group can be full access.
  All others must be restricted.

  If the Wildfly log folder is world readable or world writable, this is a
  finding."
  tag "fix": "Configure file permissions on the Wildfly log folder to protect
  from unauthorized access."
  tag "fix_id": 'F-68221r1_fix'
  describe directory("#{ attribute('jboss_home') }/standalone/log") do
    it { should_not be_readable.by 'others' }
  end
  describe directory("#{ attribute('jboss_home') }/standalone/log") do
    it { should_not be_writable.by 'others' }
  end
end
