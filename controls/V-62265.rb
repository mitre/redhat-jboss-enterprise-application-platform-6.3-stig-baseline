control 'V-62265' do
  title "Wildfly process owner execution permissions must be limited."
  desc  "Wildfly EAP application server can be run as the OS admin, which is not
  advised.  Running the application server with admin privileges increases the
  attack surface by granting the application server more rights than it requires
  in order to operate.  If the server is compromised, the attacker will have the
  same rights as the application server, which in that case would be admin
  rights.  The Wildfly EAP server must not be run as the admin user."
  impact 0.7
  tag "gtitle": 'SRG-APP-000141-AS-000095'
  tag "gid": 'V-62265'
  tag "rid": 'SV-76755r1_rule'
  tag "stig_id": 'JBOS-AS-000230'
  tag "cci": ['CCI-000381']
  tag "documentable": false
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "check": "The script that is used to start Wildfly determines the mode in
  which Wildfly will operate, which will be in either in standalone mode or domain
  mode.  Both scripts are installed by default in the $JBOSS_HOME;/bin/ folder.

  The $JBOSS_HOME default is /opt/bin/widfly

  In addition to running the Wildfly server as an interactive script launched from
  the command line, Wildfly can also be started as a service.

  The scripts used to start Wildfly are:
  Red Hat:
  standalone.sh
  domain.sh

  Windows:
  standalone.bat
  domain.bat

  Use the relevant OS commands to determine JBoss ownership.

  When running as a process:
  Red Hat: \"ps -ef|grep -i jboss\".
  Windows: \"services.msc\".

  Search for the Wildfly process, which by default is named \"Wildfly\".

  If the user account used to launch the Wildfly script or start the Wildfly process
  has admin rights on the system, this is a finding."
  tag "fix": "Run the JBoss server with non-admin rights."
  tag "fix_id": 'F-68185r1_fix'

  user = command("ps -ef | grep #{input('jboss_process_name')} | grep -v inspec | grep -v grep | awk '{print $1}'|uniq").stdout.split("\n")

  describe 'The wildly process owner' do
    subject { command("ps -ef | grep #{input('jboss_process_name')} | grep -v inspec | grep -v grep | awk '{print $1}'|uniq").stdout }
    it { should_not match(%r{root}) }
  end

  user.each do |users|
    group = command("id -gn #{users} ").stdout.split("\n")

     group.each do |group|

       describe "The wildfly process owner: #{users}\'s group" do
       subject { group }
         it { should_not eq 'root' }
       end
    end
  end
end
