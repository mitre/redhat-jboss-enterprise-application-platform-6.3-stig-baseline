control 'V-62217' do
  title "Java permissions must be set for hosted applications."
  desc  "
    The Java Security Manager is a java class that manages the external
  boundary of the Java Virtual Machine (JVM) sandbox, controlling how code
  executing within the JVM can interact with resources outside the JVM.

    The JVM requires a security policy in order to restrict application access.
   A properly configured security policy will define what rights the application
  has to the underlying system.  For example, rights to make changes to files on
  the host system or to initiate network sockets in order to connect to another
  system.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000033-AS-000024'
  tag "gid": 'V-62217'
  tag "rid": 'SV-76707r1_rule'
  tag "stig_id": 'JBOS-AS-000025'
  tag "cci": ['CCI-000213']
  tag "documentable": false
  tag "nist": ['AC-3', 'Rev_4']
  tag "check": "Obtain documentation from the admin that identifies the
  applications hosted on the JBoss server as well as the corresponding rights the
  application requires.  For example, if the application requires network socket
  permissions and file write permissions, those requirements should be documented.

  1. Identify the Wildfly installation as either domain or standalone and review
  the relevant configuration file.

  The $JBOSS_HOME default is /opt/bin/widfly

  For domain installs: JBOSS_HOME/bin/domain.conf
  For standalone installs: JBOSS_HOME/bin/standalone.conf

  2. Identify the location and name of the security policy by reading the
  JAVA_OPTS flag -Djava.security.policy=<file name> where <file name> will
  indicate name and location of security policy.  If the application uses a
  policy URL, obtain URL and policy file from system admin.

  3. Review security policy and ensure hosted applications have the appropriate
  restrictions placed on them as per documented application functionality
  requirements.

  If the security policy does not restrict application access to host resources
  as per documented requirements, this is a finding."
  tag "fix": "Configure the Java security manager to enforce access
  restrictions to the host system resources in accordance with application design
  and resource requirements."
  tag "fix_id": 'F-68137r1_fix'
  describe.one do
    describe file("#{ input('jboss_home') }/bin/standalone.conf") do
      its('content') { should match(%r{JAVA_OPTS="\$JAVA_OPTS -Djavax.security.policy=\/usr\/lib\/jvm\/java\-1.8.0\/jre\/lib\/security\/java.policy"}) }
    end
    describe file("#{ input('jboss_home') }/bin/standalone.conf") do
      its('content') { should match(%r{JAVA_OPTS="\$JAVA_OPTS -Djava.security.manager -Djava.security.policy==%JBOSS_HOME\\lib\\security\\java.policy.policy -Djboss.home.dir=%JBOSS_HOME% -Djboss.modules.policy-permissions=true"}) }
    end
  end
end
