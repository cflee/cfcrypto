require "rake/testtask"
require "rubocop/rake_task"

task default: [:rubocop, :test]

desc "Run tests"
Rake::TestTask.new do |t|
  # List of directories to added to $LOAD_PATH before running the tests.
  # (default is 'lib')
  t.libs << "test"
end

desc "Run rubocop"
task :rubocop do
  RuboCop::RakeTask.new
end
