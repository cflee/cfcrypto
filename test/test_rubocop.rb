# http://blog.trueheart78.com/ruby/2016/09/18/make-rubocop-part-of-your-tests.html

class RubocopTest < Minitest::Test
  def subject
    `rubocop`
  end

  def test_no_offenses_found
    assert_match(/no\ offenses\ detected/, subject)
  end
end
