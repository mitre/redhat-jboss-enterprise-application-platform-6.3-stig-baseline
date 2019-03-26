CONNECT= attribute(
  'connection',
  description: 'Command used to connect to the wildfly instance',
  default: '--connect'
)

control "V-62269" do
  title "Remote access to JMX subsystem must be disabled."
  desc  "The JMX subsystem allows you to trigger JDK and application management
  operations remotely.  In a managed domain configuration, the JMX subsystem is
  removed by default. For a standalone configuration, it is enabled by default
  and must be removed."
  impact 0.5
  tag "gtitle": "SRG-APP-000141-AS-000095"
  tag "gid": "V-62269"
  tag "rid": "SV-76759r1_rule"
  tag "stig_id": "JBOS-AS-000240"
  tag "cci": ["CCI-000381"]
  tag "documentable": false
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.

  The $JBOSS_HOME default is /opt/bin/widfly

  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script to start the Command Line Interface (CLI).
  Connect to the server and authenticate.

  For a Managed Domain configuration, you must check each profile name:

  For each PROFILE NAME, run the command:
  \"ls /profile=<PROFILE NAME>/subsystem=jmx/remoting-connector\"

  For a Standalone configuration:
  \"ls /subsystem=jmx/remoting-connector\"

  If \"jmx\" is returned, this is a finding."
  tag "fix": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.
  Run the jboss-cli script to start the Command Line Interface (CLI).
  Connect to the server and authenticate.

  For a Managed Domain configuration you must check each profile name:

  For each PROFILE NAME, run the command:
  \"/profile=<PROFILE NAME>/subsystem=jmx/remoting-connector=jmx:remove\"

  For a Standalone configuration:
  \"/subsystem=jmx/remoting-connector=jmx:remove\""
  tag "fix_id": "F-68189r1_fix"
  describe 'The wildfly remote access' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /subsystem=jmx/remoting-connector").stdout }
    it { should_not match(%r{jmx}) }
  end 
end

