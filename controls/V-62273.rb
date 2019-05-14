control 'V-62273' do
  title "Any unapproved applications must be removed."
  desc  "Extraneous services and applications running on an application server
  expands the attack surface and increases risk to the application server.
  Securing any server involves identifying and removing any unnecessary services
  and, in the case of an application server, unnecessary and/or unapproved
  applications."
  impact 0.5
  tag "gtitle": 'SRG-APP-000141-AS-000095'
  tag "gid": 'V-62273'
  tag "rid": 'SV-76763r1_rule'
  tag "stig_id": 'JBOS-AS-000250'
  tag "cci": ['CCI-000381']
  tag "documentable": false
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
  allow access to Wildfly.
  Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  Run the jboss-cli script.
  Connect to the server and authenticate.
  Run the command:

  ls /deployment

  The list of deployed applications is displayed.  Have the system admin identify
  the applications listed and confirm they are approved applications.

  If the system admin cannot provide documentation proving their authorization
  for deployed applications, this is a finding."
  tag "fix": "Identify, authorize, and document all applications that are
  deployed to the application server.  Remove unauthorized applications."
  tag "fix_id": 'F-68193r1_fix'

  connect = attribute('connection')
  approved_applications = attribute('approved_applications')

  applications_deployed = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{connect} --commands=ls\\ /deployment").stdout.split("\n")

  applications_deployed.each do |app|
    a = app.strip
    describe "The installed wildfly application: #{a}" do
      subject "#{a}"
      it { should be_in approved_applications }
    end
  end
  if applications_deployed.empty?
    impact 0.0
    describe 'There are no applications installed on the wildfly server, therefore this control is Not Applicable' do
      skip 'There are no applications installed on the wildfly server, therefore this control is Not Applicable'
    end
  end
end
