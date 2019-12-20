control 'V-62233' do
  title "Wildfly must be configured to allow only the ISSM (or individuals or
roles appointed by the ISSM) to select which loggable events are to be logged."
  desc  "
    The Wildfly server must be configured to select which personnel are assigned
the role of selecting which loggable events are to be logged.
    In Wildfly, the role designated for selecting auditable events is the
\"Auditor\" role.
    The personnel or roles that can select loggable events are only the ISSM
(or individuals or roles appointed by the ISSM).
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000090-AS-000051'
  tag "gid": 'V-62233'
  tag "rid": 'SV-76723r1_rule'
  tag "stig_id": 'JBOS-AS-000085'
  tag "cci": ['CCI-000171']
  tag "documentable": false
  tag "nist": ['AU-12 b', 'Rev_4']
  tag "check": "Log on to the OS of the Wildfly server with OS permissions that
allow access to Wildfly.
Using the relevant OS commands and syntax, cd to the $JBOSS_HOME;/bin/ folder.

The $JBOSS_HOME default is /opt/bin/widfly
Run the jboss-cli script to start the Command Line Interface (CLI).
Connect to the server and authenticate.
Run the command:

For a Managed Domain configuration:
\"ls
host=master/server/<SERVERNAME>/core-service=management/access=authorization/role-mapping=Auditor/include=\"

For a Standalone configuration:
\"ls
/core-service=management/access=authorization/role-mapping=Auditor/include=\"

If the list of users in the Auditors group is not approved by the ISSM, this is
a finding."
  tag "fix": "Obtain documented approvals from ISSM, and assign the appropriate
personnel into the \"Auditor\" role."
  tag "fix_id": 'F-68153r1_fix'

  connect = input('connection')
  auditor_role_users = input('auditor_role_users')

  auditor_role = command("/bin/sh #{ input('jboss_home') }/bin/jboss-cli.sh #{connect} --commands=ls\ /core-service=management/access=authorization/role-mapping=Auditor/include=").stdout.split("\n")

  auditor_role.each do |user|
    a = user.strip
    describe "#{a}" do
      it { should be_in auditor_role_users }
    end
  end
  if auditor_role.empty?
    impact 0.0
    describe 'There are no wildfly users with the auditor role, therefore this control is not applicable' do
      skip 'There are no wildfly users with the auditor role, therefore this control is not applicable'
    end
  end
end
