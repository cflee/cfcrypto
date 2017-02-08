require "openssl"

module Cfcrypto
  def self.hex2str(str)
    [str].pack("H*")
  end

  def self.str2hex(str)
    str.unpack("H*").first
  end

  def self.b64encode(bin)
    # encode without newlines
    [bin].pack("m0")
  end

  def self.b64decode(str)
    # decode with or without newlines
    str.unpack("m").first
  end

  def self.xor(str1, str2)
    # byte strings, so check length of String#bytes array, not String#length
    # as some sequences may get interpreted as Unicode chars
    raise "strings must be same length" if str1.bytes.length != str2.bytes.length
    str1.bytes.zip(str2.bytes).map { |a, b| a ^ b }.pack("C*")
  end

  def self.xor_key(str1, key)
    str2 = key * (str1.length.to_f / key.length).ceil
    str2 = str2[0..str1.length - 1]
    xor(str1, str2)
  end

  def self.chi_squared(obs, exp)
    # Pearson's chi-squared test of goodness of fit
    # obs and exp are arrays
    raise "Distributions must be same length" if obs.length != exp.length
    obs.zip(exp).map { |a, b| ((a.to_f - b)**2) / b }.inject(0, &:+)
  end

  def self.count_freq(str)
    # only count alphabetical characters, not numbers or special chars
    str.upcase.gsub(/[^A-Z]/, "").chars
      .each_with_object({}) { |x, m| m[x].nil? ? m[x] = 1 : m[x] += 1 }
  end

  def self.alpha_hash_to_array(hash)
    result = Array.new(26) { 0 }
    hash.each { |k, v| result[k.ord - "A".ord] = v }
    result
  end

  ENGLISH_FREQ = {
    "E" => 12.49, "T" => 9.28, "A" => 8.04, "O" => 7.64, "I" => 7.57,
    "N" => 7.23, "S" => 6.51, "R" => 6.28, "H" => 5.05, "L" => 4.07,
    "D" => 3.82, "C" => 3.34, "U" => 2.73, "M" => 2.51, "F" => 2.40,
    "P" => 2.14, "G" => 1.87, "W" => 1.68, "Y" => 1.66, "B" => 1.48,
    "V" => 1.05, "K" => 0.54, "X" => 0.23, "J" => 0.16, "Q" => 0.12,
    "Z" => 0.09
  }.freeze

  def self.english_score(str)
    # lower the better: closer to English letter frequency
    english_freq = {}
    ENGLISH_FREQ.map { |k, v| english_freq[k] = v.to_f / 100 * str.length }
    str_freq = count_freq(str)
    chi_squared(alpha_hash_to_array(str_freq), alpha_hash_to_array(english_freq))
  end

  def self.attack_1char_xor(str)
    # given a ciphertext byte string, find the most likely single-char xor key
    min_score = 1e100
    best_key = ""
    0.upto(255) do |i|
      key = i.chr.to_s * str.length
      dec = xor(str, key)

      # heuristic: there should be no unprintable chars in plaintext
      next if dec.gsub(/[^[:print:]]\x00/, "").length < 0.9 * dec.length

      # heuristic: there shouldn't be too many numbers, symbols
      next if dec.gsub(/[^A-Za-z ]/, "").length < 0.85 * dec.length

      score = english_score(dec)
      if score < min_score
        min_score = score
        best_key = key
      end
    end
    [best_key, min_score]
  end

  def self.attack_find_1char_xor(strs)
    # given an array of byte strings, find one that's most likely to be
    # encrypted with single-char xor
    min_score = 1e100
    likely_string = ""
    likely_key = ""
    strs.each do |s|
      key, score = attack_1char_xor(s)
      next if score > min_score

      min_score = score
      likely_string = s
      likely_key = key
    end
    [likely_string, likely_key]
  end

  def self.hamming_dist(str1, str2)
    # xor together, then compute hamming weight
    xor(str1, str2).unpack("B*").first.count("1")
  end

  def self.attack_xor_key(str)
    # determine likely key lengths
    keysizes = []
    2.upto(40) do |keysize|
      # compute hamming distance of first keysize-length block against
      # all subsequent ones, because just computing for the first two blocks
      # yielded invalid key sizes at the top
      dist_sum = 0
      1.upto((str.length / keysize) - 1) do |i|
        dist_sum += hamming_dist(str[0, keysize], str[i * keysize, keysize])
      end
      # could also compute an average of the hamming dist for each block
      # combo... but we just need to normalize over str length here, sama-sama
      norm_dist = dist_sum.to_f / str.length
      keysizes << { keysize: keysize, norm_dist: norm_dist }
    end
    keysizes.sort_by! { |x| x[:norm_dist] }

    # try top-k most likely keysizes (least hamming distance between blocks)
    min_score = 1e100
    best_key = ""
    keysizes[0, 3].each do |cand|
      # split into virtual blocks that contain ciphertext bytes for each byte
      # of the key. so if keysize is 5, then each block contains every 5th byte
      blocks_qty = cand[:keysize]
      blocks = Array.new(blocks_qty) { [] }
      str.chars.each_with_index do |e, i|
        blocks[i % blocks_qty] << e
      end

      # find most likely key for each virtual block
      cand_key = ""
      blocks.each do |b|
        key, = attack_1char_xor(b.join(""))
        cand_key << key[0] if !key.nil? && !key.empty?
      end

      # skip this keysize if there's no viable candidate key
      next if cand_key.length < cand[:keysize]

      # compute english score to pick the best keysize (lowest score)
      cand_score = english_score(xor_key(str, cand_key))
      if cand_score < min_score
        min_score = cand_score
        best_key = cand_key
      end
    end

    best_key
  end

  def self.aes_ecb_encrypt(key, msg, padding = true)
    cipher = OpenSSL::Cipher.new "AES-128-ECB"
    # important to choose mode before assigning key, etc
    # see: https://bugs.ruby-lang.org/issues/8720
    cipher.encrypt
    cipher.key = key
    cipher.padding = padding ? 1 : 0
    # no IV for ECB mode

    # call Cipher#final to ensure the last block of data is handled correctly
    cipher.update(msg) + cipher.final
  end

  def self.aes_ecb_decrypt(key, msg, padding = true)
    cipher = OpenSSL::Cipher.new "AES-128-ECB"
    # important to choose mode before assigning key, etc
    # see: https://bugs.ruby-lang.org/issues/8720
    cipher.decrypt
    cipher.key = key
    cipher.padding = padding ? 1 : 0
    # no IV for ECB mode

    # call Cipher#final to ensure the last block of data is handled correctly
    cipher.update(msg) + cipher.final
  end

  def self.split_blocks(str, size)
    # split a string into an array of blocks: strings of certain size
    res = []
    (str.length.to_f / size).ceil.times do |i|
      res << str[i * size..(i + 1) * size - 1]
    end
    res
  end

  def self.detect_ecb(strs)
    # array of ciphertext blocks of a particular size
    identical_count = 0
    strs.each_with_index do |s, i|
      next if i.zero?
      identical_count += 1 if strs[0] == s
    end
    identical_count.positive?
  end

  def self.detect_ecb_from_list(strs, size)
    # array of ciphertexts
    result = []
    strs.each_with_index do |str, i|
      blocks = split_blocks(str, size)
      result << i if detect_ecb(blocks)
    end
    result
  end

  def self.pkcs7_padding(str, size)
    remainder = size - (str.length % size)
    str + remainder.chr * remainder
  end

  def self.pkcs7_padding_remove(str)
    qty = str[-1].ord
    str[0..(-1 * qty) - 1]
  end

  def self.aes_cbc_encrypt(iv, key, msg)
    blocks = split_blocks(pkcs7_padding(msg, 16), 16)
    ciphertexts = []

    # prev ciphertext block
    prev_block = iv
    blocks.map do |b|
      prev_block = aes_ecb_encrypt(key, xor(prev_block, b), false)
      ciphertexts << prev_block
    end

    ciphertexts.join("")
  end

  def self.aes_cbc_decrypt(iv, key, msg)
    blocks = split_blocks(msg, 16)
    plaintexts = []

    # prev ciphertext block
    prev_block = iv
    blocks.each do |b|
      # must decrypt with padding OFF so that it's possible to decrypt a single
      # 16-byte block of ciphertext (instead of having 2 blocks, 2nd is padding)
      xored_plaintext = aes_ecb_decrypt(key, b, false)
      plaintexts << xor(prev_block, xored_plaintext)
      prev_block = b
    end

    plaintexts[-1] = pkcs7_padding_remove(plaintexts[-1])

    plaintexts.join("")
  end
end
