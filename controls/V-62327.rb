control "V-62327" do
  title "The JRE installed on the Wildfly server must be kept up to date."
  desc  "The Wildfly product is available as Open Source; however, the Red Hat
  vendor provides updates, patches and support for the Wildfly product.  It is
  imperative that patches and updates be applied to Wildfly in a timely manner as
  many attacks against Wildfly focus on unpatched systems.  It is critical that
  support be obtained and made available."
  impact 0.7
  tag "gtitle": "SRG-APP-000456-AS-000266"
  tag "gid": "V-62327"
  tag "rid": "SV-76817r1_rule"
  tag "stig_id": "JBOS-AS-000685"
  tag "cci": ["CCI-002605"]
  tag "documentable": false
  tag "nist": ["SI-2 c", "Rev_4"]
  tag "check": "Interview the system admin and obtain details on their patch
  management processes as it relates to the OS and the Application Server.

  If there is no active, documented patch management process in use for these
  components, this is a finding."
  tag "fix": "Configure the operating system and the application server to use
  a patch management system or process that ensures security-relevant updates are
  installed within the time period directed by the ISSM."
  tag "fix_id": "F-68247r1_fix"
  describe.one do
    describe package('java-1.7.0-openjdk') do
      its('version') { should cmp >= '1.7.0.171' }
    end
    describe package('java-1.8.0-openjdk') do
      its('version') { should cmp >= '1.8.0.161' }
    end
  end   
end

