require "test_helper"
require "cfcrypto"

class CfcryptoTest < Minitest::Test
  def test_hex_base64
    assert_equal "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", \
      Cfcrypto.b64encode(Cfcrypto.hex2str("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
  end

  def test_base64_hex
    assert_equal("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
      Cfcrypto.str2hex(Cfcrypto.b64decode("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))
  end

  def test_hex_xor
    input1 = Cfcrypto.hex2str("1c0111001f010100061a024b53535009181c")
    input2 = Cfcrypto.hex2str("686974207468652062756c6c277320657965")
    result = Cfcrypto.xor(input1, input2)
    assert_equal "746865206b696420646f6e277420706c6179", Cfcrypto.str2hex(result)
  end

  def test_chi_squared
    # obs, exp
    assert_equal 0, Cfcrypto.chi_squared([0.4, 0.6], [0.4, 0.6])
    assert_equal 1, Cfcrypto.chi_squared([0, 0], [0.4, 0.6])
    assert_in_delta 19.583, Cfcrypto.chi_squared(
      [50, 45, 5],
      [30, 60, 10]
    )
  end

  def test_count_freq
    h = { "A" => 3, "B" => 2, "C" => 1 }
    assert_equal h, Cfcrypto.count_freq("AABACB")
    h = { "A" => 3, "B" => 2, "C" => 1 }
    assert_equal h, Cfcrypto.count_freq("aabacb")
    h = { "Z" => 1, "Y" => 1 }
    assert_equal h, Cfcrypto.count_freq("zy")
    h = { "Z" => 1, "Y" => 1 }
    assert_equal h, Cfcrypto.count_freq(" z y ")
  end

  def test_english_score
    assert_in_delta 77.621, Cfcrypto.english_score("The quick brown fox jumped over the lazy black dog")
  end

  def test_attack_1char_xor
    input = Cfcrypto.hex2str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    key, = Cfcrypto.attack_1char_xor(input)
    plaintext = Cfcrypto.xor(input, key)

    assert_equal "Cooking MC's like a pound of bacon", plaintext
  end

  def test_attack_find_1char_xor
    inputs = File.readlines("test/1-4.txt").map(&:chomp)
      .map { |l| Cfcrypto.hex2str(l) }
    string, key = Cfcrypto.attack_find_1char_xor(inputs)
    plaintext = Cfcrypto.xor(string, key)
    assert_equal "Now that the party is jumping\x0a", plaintext
  end

  def test_xor_key
    input = <<~HEREDOC.chomp # remove trailing newline due to heredoc
      Burning 'em, if you ain't quick and nimble
      I go crazy when I hear a cymbal
      HEREDOC
    key = "ICE"
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    observed = Cfcrypto.str2hex(Cfcrypto.xor_key(input, key))
    assert_equal expected, observed
  end

  def test_hamming_dist
    input1 = "this is a test"
    input2 = "wokka wokka!!!"
    assert_equal 37, Cfcrypto.hamming_dist(input1, input2)
  end

  def test_attack_xor_key
    input = Cfcrypto.b64decode(File.readlines("test/1-6.txt").join(""))
    # need to separate expected output into a file because every line has
    # a single trailing space that text editors like to eat
    expected = File.readlines("test/1-6-expected.txt").join("")

    key = Cfcrypto.attack_xor_key(input)
    plaintext = Cfcrypto.xor_key(input, key)
    assert_equal expected, plaintext
  end

  def test_aes_ecb_decrypt
    input = Cfcrypto.b64decode(File.readlines("test/1-7.txt").join(""))
    expected = File.readlines("test/1-7-expected.txt").join("")
    key = "YELLOW SUBMARINE"
    plaintext = Cfcrypto.aes_ecb_decrypt(key, input)
    assert_equal expected, plaintext
  end

  def test_split_blocks
    assert_equal %w(01234567 89abcdef), Cfcrypto.split_blocks("0123456789abcdef", 8)
    assert_equal %w(01234567 89abcd), Cfcrypto.split_blocks("0123456789abcd", 8)
  end

  def test_detect_ecb
    blocks = []
    assert_equal false, Cfcrypto.detect_ecb(blocks)

    blocks = %w(abcabcab defdefde abcabccc)
    assert_equal false, Cfcrypto.detect_ecb(blocks)

    blocks << "abcabcab"
    assert_equal true, Cfcrypto.detect_ecb(blocks)
  end

  def test_detect_ecb_from_list
    x_input = %w(
      aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbaaaaaaaaaaaaaaab
      aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaa
      aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbb
      aaaaaaaaaaaaaaaabbbbbbbbbbbbbbb
    )
    assert_equal [1, 2], Cfcrypto.detect_ecb_from_list(x_input, 16)
    assert_equal [0, 1, 2, 3], Cfcrypto.detect_ecb_from_list(x_input, 8)

    # TODO: figure out why this isn't passing
    # input = File.readlines("test/1-8.txt").map { |x| Cfcrypto.hex2str(x.chomp) }
    # assert_equal [0], Cfcrypto.detect_ecb_from_list(input, 16)
  end
end
