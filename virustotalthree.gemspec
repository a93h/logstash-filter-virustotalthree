Gem::Specification.new do |s|
  s.name          = 'logstash-filter-virustotalthree'
  s.version       = '0.1.2'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'This filter queries the Virustotal API v3'
  s.description   = 'This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program'
  s.homepage      = 'https://github.com/a93h/logstash-filter-virustotalthree'
  s.authors       = ["gh-flo-vall","CoolAcid","a93h"]
  s.email         = ''
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency 'virustotalx', '1.2.0'
  s.add_development_dependency 'logstash-devutils'
end
