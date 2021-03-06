# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{halberd}
  s.version = "0.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = [%q{Paul Zhang}]
  s.date = %q{2011-09-03}
  s.description = %q{Connect to Yodlee. Yay!}
  s.email = %q{paul.zhang@debteye.com}
  s.extra_rdoc_files = [
    "README.md"
  ]
  s.files = [
    "Gemfile",
    "Gemfile.lock",
    "README.md",
    "Rakefile",
    "VERSION",
    "config/halberd.yml",
    "halberd.gemspec",
    "lib/halberd.rb",
    "lib/halberd/utils.rb",
    "spec/halberd_spec.rb",
    "spec/spec_helper.rb"
  ]
  s.homepage = %q{http://www.debteye.com}
  s.require_paths = [%q{lib}]
  s.rubygems_version = %q{1.8.6}
  s.summary = %q{Yodlee Ruby Connect.}

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<halberd>, [">= 0"])
      s.add_development_dependency(%q<rspec>, ["~> 2.6.0"])
      s.add_development_dependency(%q<rspec>, ["~> 2.6.0"])
      s.add_development_dependency(%q<rspec>, ["~> 2.6.0"])
      s.add_runtime_dependency(%q<orderedhash>, ["~> 0.0.6"])
      s.add_runtime_dependency(%q<savon_model>, ["~> 1.0.0"])
      s.add_runtime_dependency(%q<savon>, ["~> 1.2.0"])
    else
      s.add_dependency(%q<halberd>, [">= 0"])
      s.add_dependency(%q<rspec>, ["~> 2.6.0"])
      s.add_dependency(%q<rspec>, ["~> 2.6.0"])
      s.add_dependency(%q<rspec>, ["~> 2.6.0"])
      s.add_dependency(%q<orderedhash>, ["~> 0.0.6"])
      s.add_dependency(%q<savon_model>, ["~> 1.0.0"])
      s.add_dependency(%q<savon>, ["~> 1.2.0"])
    end
  else
    s.add_dependency(%q<halberd>, [">= 0"])
    s.add_dependency(%q<rspec>, ["~> 2.6.0"])
    s.add_dependency(%q<rspec>, ["~> 2.6.0"])
    s.add_dependency(%q<rspec>, ["~> 2.6.0"])
    s.add_dependency(%q<orderedhash>, ["~> 0.0.6"])
    s.add_dependency(%q<savon_model>, ["~> 1.0.0"])
    s.add_dependency(%q<savon>, ["~> 1.2.0"])
  end
end

