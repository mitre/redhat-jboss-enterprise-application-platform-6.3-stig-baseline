CONNECT= attribute(
  'connection',
  description: 'Minimum Web vendor-supported version.',
  default: '' 
)

AUDITOR_ROLE_USERS= attribute(
  'auditor_role_users',
  description: 'List of authorized users with the auditor role.',
  default: %w[
            user-auditor 
           ]
)

ADMINISTRATOR_ROLE_USERS= attribute(
  'administrator_role_users',
  description: 'List of authorized users with the administrator role.',
  default: %w[
            user-admin
           ]
)

SUPERUSER_ROLE_USERS= attribute(
  'superuser_role_users',
  description: 'List of authorized users with the SuperUser role.',
  default: %w[
            user-superuser 
            user-$local
           ]
)

control "V-62219" do
  title "Users in JBoss Management Security Realms must be in the appropriate role"
  desc  "
    Security realms are a series of mappings between users and passwords and
users and roles.  There are 2 JBoss security realms provided by default; they
are \"management realm\" and \"application realm\".

    Management realm stores authentication information for the management API,
which provides functionality for the web-based management console and the
management command line interface (CLI).

    mgmt-groups.properties stores user to group mapping for the ManagementRealm
but only when role-based access controls  (RBAC) is enabled.

    If management users are not in the appropriate role, unauthorized access to
JBoss resources can occur.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000033-AS-000024"
  tag "gid": "V-62219"
  tag "rid": "SV-76709r1_rule"
  tag "stig_id": "JBOS-AS-000040"
  tag "cci": ["CCI-000213"]
  tag "documentable": false
  tag "nist": ["AC-3", "Rev_4"]
  tag "check": "Review the mgmt-users.properties file.   Also review the
<management /> section in the standalone.xml or domain.xml configuration files.
 The relevant xml file will depend on if the Wildfly server is configured in
standalone or domain mode.

Ensure all users listed in these files are approved for management access to
the JBoss server and are in the appropriate role.

The $JBOSS_HOME default is /opt/bin/widfly

For domain configurations:
$JBOSS_HOME;/domain/configuration/mgmt-users.properties.
$JBOSS_HOME;/domain/configuration/domain.xml

For standalone configurations:
$JBOSS_HOME;/standalone/configuration/mgmt-users.properties.
$JBOSS_HOME;/standalone/configuration/standalone.xml

If the users listed are not in the appropriate role, this is a finding."
  tag "fix": "Document approved management users and their roles.  Configure
the application server to use RBAC and ensure users are placed into the
appropriate roles."
  tag "fix_id": "F-68139r1_fix"

  role_mappings = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/access=authorization/role-mapping=").stdout.strip.split(" ")

  # obtains all users with the administrator role
  # obtains all users with the auditor role


  auditor_role = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Auditor/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  # obtains all users with the administrator role
  administrator_role = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/access=authorization/role-mapping=Administrator/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")

  # obtains all users with the SuperUser role
  superuser_role = command("/bin/sh /opt/wildfly/bin/jboss-cli.sh #{CONNECT} --commands=ls\\ /core-service=management/access=authorization/role-mapping=SuperUser/include= | grep -v 'Manage' | grep -v 'core' | grep -v 'access' | grep -v 'mapping' | grep -v 'not found'").stdout.strip.split(" ")
  
  if !auditor_role.empty?
    auditor_role.each do |user|
      describe "#{user}" do
        it { should be_in AUDITOR_ROLE_USERS}
      end   
    end
  end

  if !administrator_role.empty?
    administrator_role.each do |user|
      describe "#{user}" do
        it { should be_in ADMINISTRATOR_ROLE_USERS}
      end  
    end   
  end

  if !superuser_role.empty?
    superuser_role.each do |user|
     describe "#{user}" do
        it { should be_in SUPERUSER_ROLE_USERS}
      end   
    end
  end

  if auditor_role.empty? && administrator_role.empty? && superuser_role.empty?
    impact 0.0
    desc 'There are no Wildfly users with the auditor, administrator or superuser roles, therefore this control is not applicable'
    describe 'There are no Wildfly users with the auditor, administrator or superuser roles, therefore this control is not applicable' do
      skip 'There are no Wildfly users with the auditor, administrator or superuser roles, therefore this control is not applicable'
    end
  end
end