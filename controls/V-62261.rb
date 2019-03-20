control "V-62261" do
  title "Wildfly process owner interactive access must be restricted."
  desc  "Wildfly does not require admin rights to operate and should be run as a
  regular user.  In addition, if the user account was to be compromised and the
  account was allowed interactive logon rights, this would increase the risk and
  attack surface against the Wildfly system.  The right to interactively log on to
  the system using the Wildfly account should be limited according to the OS
  capabilities."
  impact 0.7
  tag "gtitle": "SRG-APP-000141-AS-000095"
  tag "gid": "V-62261"
  tag "rid": "SV-76751r1_rule"
  tag "stig_id": "JBOS-AS-000220"
  tag "cci": ["CCI-000381"]
  tag "documentable": false
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "Identify the user account used to run the Wildfly server.  Use
  relevant OS commands to determine logon rights to the system. This account
  should not have full shell/interactive access to the system.

  If the user account used to operate Wildfly can log on interactively, this is a
  finding."
  tag "fix": "Use the relevant OS commands to restrict Wildfly user account from
  interactively logging on to the console of the Wildfly system.

  For Windows systems, use GPO.

  For UNIX like systems using ssh DenyUsers <account id> or follow established
  procedure for restricting access."
  tag "fix_id": "F-68181r1_fix"
  wildfly_process_owners = command("ps -aux | grep wildfly | grep -v 'color=auto wildfly' | grep -v chef | grep -v grep | awk '{print $1}'").stdout.split("\n")

  wildfly_process_owners.each do |owner|
    get_shell_bin_false = command("awk -F : '$1 == \"#{owner}\" { print $7}' /etc/passwd").stdout
    get_shell_sbin_nologin = command("awk -F : '$1 == \"#{owner}\" { print $7}' /etc/passwd").stdout
    get_shell_usr_sbin_nologin = command("awk -F : '$1 == \"#{owner}\" { print $7}' /etc/passwd").stdout
    
    describe.one do
      describe "The wildfly process owner: #{owner}\'s shell/interactive access" do
        subject { get_shell_bin_false }
        it { should match(%r{/bin/false}) }
      end
      describe "The wildfly process owner: #{owner}\'s shell/interactive access" do
        subject { get_shell_sbin_nologin }
        it { should match(%r{/sbin/nologin}) }
      end
      describe "The wildfly process owner: #{owner}\'s shell/interactive access" do
        subject { get_shell_usr_sbin_nologin }
        it { should match(%r{/usr/sbin/nologin}) }
      end
    end
  end  
end

