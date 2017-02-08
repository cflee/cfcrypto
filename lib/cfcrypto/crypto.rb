module Cfcrypto
  def self.hex2str(str)
    [str].pack('H*')
  end

  def self.str2hex(str)
    str.unpack('H*').first
  end

  def self.b64encode(bin)
    [bin].pack('m0')
  end

  def self.b64decode(str)
    str.unpack('m0').first
  end

  # def self.hex_xor(buf1, buf2)
  #   # hex strings
  #   raise "Buffers must be same length" if buf1.length != buf2.length
  #   in1 = hex2str(buf1)
  #   in2 = hex2str(buf2)
  #   res = in1.bytes.zip(in2.bytes).map { |a, b| a^b }.pack('C*')
  #   str2hex(res)
  # end

  def self.xor(buf1, buf2)
    # byte strings
    raise "Buffers must be same length" if buf1.length != buf2.length
    res = buf1.bytes.zip(buf2.bytes).map { |a, b| a^b }.pack('C*')
    return res
  end

  def self.chi_squared(obs, exp)
    # Pearson's chi-squared test of goodness of fit
    # obs and exp are arrays
    raise "Distributions must be same length" if obs.length != exp.length
    obs.zip(exp).map { |a, b| ((a.to_f - b) ** 2) / b }.inject(0, &:+)
  end

  def self.count_freq(str)
    # only count alphabetical characters, not numbers or special chars
    str.upcase.gsub(/[^A-Z]/, '').chars
      .reduce(Hash.new) { |m, x| m[x] == nil ? m[x] = 1 : m[x] += 1; m }
  end

  def self.alpha_hash_to_array(hash)
    result = Array.new(26) { 0 }
    hash.each { |k, v| result[k.ord - 'A'.ord] = v }
    result
  end

  ENGLISH_FREQ = {
    'E' => 12.49, 'T' => 9.28, 'A' => 8.04, 'O' => 7.64, 'I' => 7.57,
    'N' => 7.23, 'S' => 6.51, 'R' => 6.28, 'H' => 5.05, 'L' => 4.07,
    'D' => 3.82, 'C' => 3.34, 'U' => 2.73, 'M' => 2.51, 'F' => 2.40,
    'P' => 2.14, 'G' => 1.87, 'W' => 1.68, 'Y' => 1.66, 'B' => 1.48,
    'V' => 1.05, 'K' => 0.54, 'X' => 0.23, 'J' => 0.16, 'Q' => 0.12,
    'Z' => 0.09
  }

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
    best_key = ''
    0.upto(255) do |i|
      key = i.chr.to_s * str.length
      dec = xor(str, key)

      # heuristic: there should be no unprintable chars in plaintext
      next if dec.gsub(/[^[:print:]]\x00/, '').length < 0.9 * dec.length

      # heuristic: there shouldn't be too many numbers, symbols
      next if dec.gsub(/[^A-Za-z ]/, '').length < 0.85 * dec.length

      score = english_score(dec)
      if score < min_score
        min_score = score
        best_key = key
      end
    end
    return best_key, min_score
  end

  def self.attack_find_1char_xor(strs)
    # given an array of byte strings, find one that's most likely to be
    # encrypted with single-char xor
    min_score = 1e100
    likely_string = ''
    likely_key = ''
    strs.each do |s|
      key, score = attack_1char_xor(s)
      if score < min_score
        min_score = score
        likely_string = s
        likely_key = key
      end
    end
    return likely_string, likely_key
  end
end
