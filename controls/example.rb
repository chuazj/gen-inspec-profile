# encoding: utf-8
# copyright: 2018, The Authors
control "2.1.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" do
  title "2.1.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  desc "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  impact 1.0
    (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeTrustedCredManAccessPrivilege") { should_not include entry }
    end
  end
end

control "2.1.2 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'" do
  title "2.1.2 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
  desc "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeTimeZonePrivilege") { should_not include entry }
    end
  end
end
    
control "2.1.3 (L1) Ensure 'Create a pagefile' is set to 'Administrators'" do
  title "2.1.3 (L1) Ensure 'Create a pagefile' is set to 'Administrators'"
  desc "Ensure 'Create a pagefile' is set to 'Administrators'"
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
      describe security_policy do
        its("SeCreatePagefilePrivilege") { should_not include entry }
    end
  end
end
  
control "2.1.4 (L1) Ensure 'Create a token object' is set to 'No One'" do
  title "2.1.4 (L1) Ensure 'Create a token object' is set to 'No One'"
  desc "Ensure 'Create a token object' is set to 'No One'"
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeCreateTokenPrivilege") { should_not include entry }
    end
  end
end
    
control "2.1.5 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" do
  title "2.1.5 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  impact 1.0
  a = (((((((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-20']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-6'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeCreateGlobalPrivilege") { should_not include entry }
    end
  end
end
