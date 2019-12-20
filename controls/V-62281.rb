control 'V-62281' do
  title "The Wildfly server must be configured to use individual accounts and not
  generic or shared accounts."
  desc  "
    To assure individual accountability and prevent unauthorized access,
  application server users (and any processes acting on behalf of application
  server users) must be individually identified and authenticated.

      A group authenticator is a generic account used by multiple individuals.
  Use of a group authenticator alone does not uniquely identify individual users.

      Application servers must ensure that individual users are authenticated
  prior to authenticating via role or group authentication. This is to ensure
  that there is non-repudiation for actions taken.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000153-AS-000104'
  tag "gid": 'V-62281'
  tag "rid": 'SV-76771r1_rule'
  tag "stig_id": 'JBOS-AS-000275'
  tag "cci": ['CCI-000770']
  tag "documentable": false
  tag "nist": ['IA-2 (5)', 'Rev_4']
  tag "check": "If the application server management interface is configured to
  use LDAP authentication this requirement is NA.

  Determine the mode in which the Wildfly server is operating by authenticating to
  the OS, changing to the $JBOSS_HOME;/bin/ folder and executing the jboss-cli
  script.

  The $JBOSS_HOME default is /opt/bin/widfly

  Connect to the server and authenticate.
  Run the command: \"ls\" and examine the \"launch-type\" setting.

  User account information is stored in the following files for a Wildfly server
  configured in standalone mode.  The command line flags passed to the
  \"standalone\" startup script determine the standalone operating mode:
  $JBOSS_HOME;/standalone/configuration/standalone.xml
  $JBOSS_HOME;/standalone/configuration/standalone-full.xml
  $JBOSS_HOME;/standalone/configuration/standalone.-full-ha.xml
  $JBOSS_HOME;/standalone/configuration/standalone.ha.xml

  For a Managed Domain:
  $JBOSS_HOME;/domain/configuration/domain.xml.

  Review both files for generic or shared user accounts.

  Open each xml file with a text editor and locate the <management-interfaces>
  section.
  Review the <user name = \"xxxxx\"> sub-section where \"xxxxx\" will be a user
  name.

  Have the system administrator identify the user of each user account.

  If user accounts are not assigned to individual users, this is a finding."
  tag "fix": "Configure the application server so required users are
  individually authenticated by creating individual user accounts.  Utilize an
  LDAP server that is configured according to DOD policy."
  tag "fix_id": 'F-68201r1_fix'

  connect = input('connection')
  auditor_role_users = input('auditor_role_users')
  administrator_role_users = input('administrator_role_users')
  superuser_role_users = input('superuser_role_users')
  deployer_role_users = input('deployer_role_users')
  maintainer_role_users = input('maintainer_role_users')
  monitor_role_users = input('monitor_role_users')
  operator_role_users = input('operator_role_users')

  auditor_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Auditor/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  administrator_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Administrator/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  superuser_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/role-mapping=SuperUser/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  deployer_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Deployer/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  maintainer_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Maintainer/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  monitor_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Monitor/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  operator_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Operator/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")

  if !auditor_role.empty?
    auditor_role.each do |user|
      describe "User: #{user} with the auditor role" do
        subject { user }
        it { should be_in auditor_role_users }
      end
    end
  end

  if !administrator_role.empty?
    administrator_role.each do |user|
      describe "User: #{user} with the administrator role" do
        subject { user }
        it { should be_in administrator_role_users }
      end
    end
  end

  if !superuser_role.empty?
    superuser_role.each do |user|
      describe "User: #{user} with the SuperUser role" do
        subject { user }
        it { should be_in superuser_role_users }
      end
    end
  end

  if !deployer_role.empty?
    deployer_role.each do |user|
      describe "User: #{user} with the deployer role" do
        subject { user }
       it { should be_in deployer_role_users }
      end
    end
  end

  if !maintainer_role.empty?
    maintainer_role.each do |user|
      describe "User: #{user} with the maintainer role" do
        subject { user }
        it { should be_in maintainer_role_users }
      end
    end
  end

  if !monitor_role.empty?
    monitor_role.each do |user|
      describe "User: #{user} with the monitor role" do
        subject { user }
        it { should be_in monitor_role_users }
      end
    end
  end

  if !operator_role.empty?
    operator_role.each do |user|
      describe "User: #{user} with the operator role" do
        subject { user }
        it { should be_in operator_role_users }
      end
    end
  end
  if auditor_role.empty? && administrator_role.empty? && superuser_role.empty? && deployer_role.empty? && maintainer_role.empty && monitor_role.empty && operator_role.empty?
    impact 0.0
    desc 'The are no Wildfly accounts with the following roles: auditor, administrator, superuser, deployer, maintainer, monitor, or operator, therefore this control is not applicable'
    describe 'The are no Wildfly accounts with the following roles: auditor, administrator, superuser, deployer, maintainer, monitor, or operator, therefore this control is not applicable' do
      skip 'The are no Wildfly accounts with the following roles: auditor, administrator, superuser, deployer, maintainer, monitor, or operator, therefore this control is not applicable'
    end
  end
end
