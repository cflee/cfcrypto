require "simplecov"

# this should be at the top to ensure all tests are recorded
SimpleCov.start do
  minimum_coverage 90
  minimum_coverage_by_file 80
  maximum_coverage_drop 5
end

require "minitest/autorun"
