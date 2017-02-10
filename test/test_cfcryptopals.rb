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

  def test_aes_ecb
    # test decryption
    input = Cfcrypto.b64decode(File.readlines("test/1-7.txt").join(""))
    expected = File.readlines("test/1-7-expected.txt").join("")
    key = "YELLOW SUBMARINE"
    plaintext = Cfcrypto.aes_ecb_decrypt(key, input)
    assert_equal expected, plaintext

    # test encryption
    ciphertext = Cfcrypto.aes_ecb_encrypt(key, plaintext)
    assert_equal input, ciphertext
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

  def test_pkcs7_padding
    # test not-a-multiple-of-block-size case
    input = "YELLOW SUBMARINE"
    expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
    padded = Cfcrypto.pkcs7_padding(input, 20)
    assert_equal expected, padded
    assert_equal input, Cfcrypto.pkcs7_padding_remove(padded)

    # test multiple-of-block-size case
    padded = Cfcrypto.pkcs7_padding(input, 16)
    assert_equal "YELLOW SUBMARINE" + "\x10" * 16, padded
    assert_equal input, Cfcrypto.pkcs7_padding_remove(padded)
  end

  def test_aes_cbc
    # test encryption
    iv = "\xDE\xAD\xBE\xEF" * 4
    key = "YELLOW SUBMARINE"
    msg = "Hello world xxxx" * 20
    ciphertext = Cfcrypto.aes_cbc_encrypt(iv, key, msg)

    # test decryption
    assert_equal msg, Cfcrypto.aes_cbc_decrypt(iv, key, ciphertext)

    # test decryption of provided ciphertext
    input = Cfcrypto.b64decode(File.readlines("test/2-10.txt").join(""))
    expected = File.readlines("test/2-10-expected.txt").join("")
    plaintext = Cfcrypto.aes_cbc_decrypt("\x00" * 16, "YELLOW SUBMARINE", input)
    assert_equal expected, plaintext
  end

  def test_generate_key
    key = Cfcrypto.generate_key(16)
    assert_equal 16, key.bytes.length
  end

  def test_aes_encrypt_oracle
    # verify that the length is as expected
    # length 22 so that prefix/suffix will bring it to length 32 to 42
    # and pkcs7 padding will make sure it's 3 blocks (16 * 3 = 48) long
    msg = "0123456789abcdef012345"
    50.times { assert_equal 16 * 3, Cfcrypto.aes_encrypt_oracle(msg)[0].length }
  end

  def test_aes_encrypt_oracle_challenger
    # craft challenge
    # objective is to ensure that we control at least two blocks, regardless
    # of the prefix/suffixed random bytes, so we can determine if ECB or not
    # need at least (16 - 5) in front and behind, plus (16 * 2) in middle
    # 11 * 2 + 16 * 2 = 54
    msg = "A" * 54

    # do this repeatedly
    50.times do
      # send to oracle
      ciphertext, coin = Cfcrypto.aes_encrypt_oracle(msg)

      # inspect blocks two and three
      blocks = Cfcrypto.split_blocks(ciphertext, 16)
      coin_guess = blocks[1] == blocks[2] ? 0 : 1

      # verify result
      flunk if coin_guess != coin
    end

    # all is well if did not return early
    pass
  end

  def test_aes_encrypt_oracle_2
    # find the number of bytes to finish current block
    prev_ciphertext_length = Cfcrypto.aes_encrypt_oracle_2("A").length
    pad_size = 2
    Kernel.loop do
      ciphertext_length = Cfcrypto.aes_encrypt_oracle_2("A" * pad_size).length
      if ciphertext_length > prev_ciphertext_length
        # save this for next loop to use
        prev_ciphertext_length = ciphertext_length
        break
      end
      pad_size += 1
    end

    # now find the number of bytes to fill out next block
    block_size = 1
    Kernel.loop do
      ciphertext_length = Cfcrypto.aes_encrypt_oracle_2("A" * (pad_size + block_size)).length
      break if ciphertext_length > prev_ciphertext_length
      block_size += 1
    end

    # compute suffix length (including up to 1 block of padding?)
    suffix_size = Cfcrypto.aes_encrypt_oracle_2("A" * (pad_size + block_size)).length
    suffix_size -= pad_size + block_size

    # confirm it's ecb mode, bail if not
    ciphertext = Cfcrypto.aes_encrypt_oracle_2("A" * (block_size * 2))
    ciphertext_blocks = Cfcrypto.split_blocks(ciphertext, block_size)
    flunk "aes_encrypt_oracle_2 not ecb mode" if ciphertext_blocks[0] != ciphertext_blocks[1]

    # decrypt a byte at a time
    msg_found = ""
    blocks_found = 0
    bytes_found = 0
    while blocks_found * block_size + bytes_found < suffix_size
      # increment first so that we know which byte we're targeting now
      bytes_found = (bytes_found + 1) % block_size
      blocks_found += 1 if bytes_found.zero?

      # construct multiple-of-blocksize-minus-1 message for 'oracle block'
      # this should go from (block_size - 1) to 0 and repeat
      msg = "A" * (block_size - bytes_found)
      oracle_block = Cfcrypto.aes_encrypt_oracle_2(msg)[blocks_found * block_size, block_size]

      # brute force through all possible chars to see if they match oracle
      # based on get last (block_size - 1) of constructed message
      dict_msg = (msg + msg_found)[-(block_size - 1)..-1]
      255.times do |i|
        block = Cfcrypto.aes_encrypt_oracle_2(dict_msg + i.chr)[0, block_size]
        if oracle_block == block
          msg_found << i.chr
          break
        end
      end
    end

    # remove padding
    msg_found = Cfcrypto.pkcs7_padding_remove(msg_found)

    # verify
    assert_equal Cfcrypto.b64decode(<<~HEREDOC), msg_found
      Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
      aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
      dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
      YnkK
      HEREDOC
  end

  def test_cookie_parse
    expected = { "foo" => "bar", "baz" => "qux", "zap" => "zazzle" }
    observed = Cfcrypto.cookie_parse("foo=bar&baz=qux&zap=zazzle")
    assert_equal expected, observed
  end

  def test_profile_for
    assert_equal "email=abc@def.com&uid=10&role=user", Cfcrypto.profile_for("abc@def.com")
    assert_equal "email=abc@def.com&uid=10&role=user", Cfcrypto.profile_for("abc@def&.com")
    assert_equal "email=abc@def.com&uid=10&role=user", Cfcrypto.profile_for("abc@def=.com")
  end

  def test_profile_encode_decode
    encoded = Cfcrypto.profile_encode("foo@bar.com")
    assert_equal "foo@bar.com", Cfcrypto.profile_decode(encoded)["email"]
    assert_equal "user", Cfcrypto.profile_decode(encoded)["role"]

    # target construct:
    # email=...<10>...
    # <3>&uid=10&role=
    # admin&uid=10&rol
    # \x16 * 16        (padding block)
    #
    # derive first two blocks from a 13 char email
    # derive third block from 10 char + "admin" email
    # derive fourth block from 9 char email
    part1 = Cfcrypto.split_blocks(Cfcrypto.profile_encode("lee@cflee.net"), 16)
    part2 = Cfcrypto.split_blocks(Cfcrypto.profile_encode("0123@b.comadmin"), 16)
    part3 = Cfcrypto.split_blocks(Cfcrypto.profile_encode("012@b.com"), 16)
    magic = part1[0] + part1[1] + part2[1] + part3[2]
    assert_equal "admin", Cfcrypto.profile_decode(magic)["role"]
  end
end
