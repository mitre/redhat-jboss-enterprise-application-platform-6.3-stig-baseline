CONNECT= attribute(
  'connection',
  description: 'Minimum Web vendor-supported version.',
  default: ''
)


control "V-62249" do
  title "Wildfly ROOT logger must be configured to utilize the appropriate
  logging level."
  desc  "
    Information system logging capability is critical for accurate forensic
  analysis. Log record content that may be necessary to satisfy the requirement
  of this control includes: time stamps, source and destination addresses,
  user/process identifiers, event descriptions, success/fail indications,
  filenames involved, and access control or flow control rules invoked.

      The Wildfly application server ROOT logger captures all messages not captured
  by a log category and sends them to a log handler (FILE, CONSOLE, SYSLOG,
  ETC.).  By default, the ROOT logger level is set to INFO, which is a value of
  800.  This will capture most events adequately.  Any level numerically higher
  than INFO (> 800) records less data and may result in an insufficient amount of
  information being logged by the ROOT logger.  This can result in failed
  forensic investigations.  The ROOT logger level must be INFO level or lower to
  provide adequate log information.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000100-AS-000063"
  tag "gid": "V-62249"
  tag "rid": "SV-76739r1_rule"
  tag "stig_id": "JBOS-AS-000135"
  tag "cci": ["CCI-001487"]
  tag "documentable": false
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.

  The $JBOSS_HOME default is /opt/bin/widfly
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script to start the Command Line Interface (CLI).
  Connect to the server and authenticate.

  The PROFILE NAMEs included with a Managed Domain Wildfly configuration are:
  \"default\", \"full\", \"full-ha\" or \"ha\"
  For a Managed Domain configuration, you must check each profile name:

  For each PROFILE NAME, run the command:
  \"ls /profile=<PROFILE NAME>/subsystem=logging/root-logger=ROOT\"

  If ROOT logger \"level\" is not set to INFO, DEBUG or TRACE
  This is a finding for each <PROFILE NAME> (default, full, full-ha and ha)

  For a Standalone configuration:
  \"ls /subsystem=logging/root-logger=ROOT\"

  If \"level\" not = INFO, DEBUG or TRACE, this is a finding."
  tag "fix": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.

  The $JBOSS_HOME default is /opt/bin/widfly
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script to start the Command Line Interface (CLI).
  Connect to the server and authenticate.

  The PROFILE NAMEs included with a Managed Domain Wildfly configuration are:
  \"default\", \"full\", \"full-ha\" or \"ha\"
  For a Managed Domain configuration, you must check each profile name:

  For each PROFILE NAME, run the command:
  \"/profile=<PROFILE
  NAME>/subsystem=logging/root-logger=ROOT:write-attribute(name=level,value=INFO)\"

  For a Standalone configuration:
  \"/subsystem=logging/root-logger=ROOT:write-attribute(name=level,value=INFO)\""
  tag "fix_id": "F-68169r1_fix"

  get_logging_level = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /subsystem=logging/root-logger=ROOT").stdout

  describe.one do 
    describe 'The wildfly root logger level' do
      subject { get_logging_level }
      it { should match(%r{level=INFO}) }
    end
    describe 'The wildfly root logger level' do
      subject { get_logging_level }
      it { should match(%r{level=DEBUG}) }
    end
    describe 'The wildfly root logger level' do
      subject { get_logging_level }
      it { should match(%r{level=TRACE}) }
    end
  end
end

