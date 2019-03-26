CONNECT= attribute(
  'connection',
  description: 'Command used to connect to the wildfly instance',
  default: '--connect'
)

control "V-62271" do
  title "Welcome Web Application must be disabled."
  desc  "The Welcome to Wildfly web page provides a redirect to the Wildfly admin
  console, which, by default, runs on TCP 9990 as well as redirects to the Online
  User Guide and Online User Groups hosted at locations on the Internet.  The
  welcome page is unnecessary and should be disabled or replaced with a valid web
  page."
  impact 0.3
  tag "gtitle": "SRG-APP-000141-AS-000095"
  tag "gid": "V-62271"
  tag "rid": "SV-76761r1_rule"
  tag "stig_id": "JBOS-AS-000245"
  tag "cci": ["CCI-000381"]
  tag "documentable": false
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "Use a web browser and browse to HTTP://Wildfly SERVER IP
  ADDRESS:8080

  If the Wildfly Welcome page is displayed, this is a finding."


  tag "fix": "Use the Management CLI script JBOSS_HOME/bin/jboss-cli.sh to run
  the following command. You may need to change the profile to modify a different
  managed domain profile, or remove the \"/profile=default\" portion of the
  command for a standalone server.

  The $JBOSS_HOME default is /opt/bin/widfly

  \"/profile=default/subsystem=web/virtual-server=default-host:writeattribute(name=enable-welcome-root,value=false)\"

  To configure your web application to use the root context (/) as its URL
  address, modify the applications jboss-web.xml, which is located in the
  applications META-INF/ or WEB-INF/ directory. Replace its <context-root>
  directive with one that looks like the following:

  <jboss-web>
           <context-root>/</context-root>
  </jboss-web>"
  tag "fix_id": "F-68191r1_fix"
  describe 'The wildfly web application' do
    subject { command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /subsystem=undertow/server=default-server/host=default-host/location=\\\/").stdout }
    it { should_not match(%r{handler=welcome-content}) }
  end 
end

