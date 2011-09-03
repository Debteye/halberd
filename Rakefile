begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name        = 'halberd'
    gemspec.summary     = 'Yodlee Ruby Connect.'
    gemspec.description = %{
      Connect to Yodlee.  Yay!
    }.strip.split.join(' ')
    gemspec.homepage    = 'http://www.debteye.com'

    gemspec.authors     = ['Paul Zhang']
    gemspec.email       = 'paul.zhang@debteye.com'

    gemspec.add_development_dependency  'rspec', '~> 2.6.0'
    gemspec.add_runtime_dependency      'orderedhash',   '~> 0.0.6'
    gemspec.add_runtime_dependency      'savon',    '~> 0.9.6'
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts 'Jeweler is not available. Install it with: `gem install jeweler`'
end

