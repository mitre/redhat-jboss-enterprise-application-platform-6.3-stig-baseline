control 'V-62267' do
  title "Wildfly QuickStarts must be removed."
  desc  "Wildfly QuickStarts are demo applications that can be deployed quickly.
Demo applications are not written with security in mind and often open new
attack vectors.  QuickStarts must be removed."
  impact 0.5
  tag "gtitle": 'SRG-APP-000141-AS-000095'
  tag "gid": 'V-62267'
  tag "rid": 'SV-76757r1_rule'
  tag "stig_id": 'JBOS-AS-000235'
  tag "cci": ['CCI-000381']
  tag "documentable": false
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "check": "Examine the $JBOSS_HOME; folder.  If a
  wildfly quickstarts folder exits, this is a finding."
  tag "fix": "Delete the QuickStarts folder."
  tag "fix_id": 'F-68187r1_fix'
  describe 'The wildfly quickstart files found' do
    subject { command("find #{ attribute('jboss_home') }/ -type d | grep quickstarts").stdout }
    it { should match(%r{}) }
  end
end
