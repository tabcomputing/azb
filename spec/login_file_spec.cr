require "./spec_helper"
require "file_utils"
require "../src/azb/login_file"

private def in_dir(&)
  dir = File.tempname("azb-login")
  Dir.mkdir(dir)
  begin
    yield dir
  ensure
    FileUtils.rm_rf(dir)
  end
end

describe AzookaBay::LoginFile do
  it "reads the settings, with the vocabulary and bodies from files beside it" do
    in_dir do |dir|
      Dir.mkdir(File.join(dir, "mail"))
      File.write(File.join(dir, "words.txt"), "# the Magic Word's syllables\nka\n\n  zo \nmi\n")
      File.write(File.join(dir, "mail", "body.txt"), "Words: {code}\n")
      File.write(File.join(dir, "login.yml"), <<-YAML)
        method: code
        code: { style: vocab, length: 4, vocab_file: words.txt, separator: "-" }
        label: Magic Word
        email: { subject: "Your Magic Word", body_file: mail/body.txt }
        fallback_email: { subject: "The words fade", body: "Touch this: {link}" }
        YAML
      f = AzookaBay::LoginFile.load(File.join(dir, "login.yml"))
      f.method.should eq "code"
      f.code_style.should eq "vocab"
      f.code_length.should eq 4
      f.vocab.should eq %w(ka zo mi) # trimmed; blanks and comments skipped
      f.separator.should eq "-"
      f.label.should eq "Magic Word"
      f.email_subject.should eq "Your Magic Word"
      f.email_body.should eq "Words: {code}\n"
      f.fallback_subject.should eq "The words fade"
      f.fallback_body.should eq "Touch this: {link}"
    end
  end

  it "can confine the files it reads to the YAML's own directory" do
    in_dir do |dir|
      Dir.mkdir(File.join(dir, "azb"))
      File.write(File.join(dir, "secret.env"), "DATABASE_URL=postgres://user:pw@host/db\n")
      File.write(File.join(dir, "azb", "body.txt"), "Words: {code}")
      File.symlink(File.join(dir, "secret.env"), File.join(dir, "azb", "link.txt"))
      path = File.join(dir, "azb", "login.yml")
      File.write(path, "method: code\nemail: { body_file: body.txt }\n")
      AzookaBay::LoginFile.load(path, confine: true).email_body.should eq "Words: {code}"
      { {"../secret.env", /lies outside/}, {"link.txt", /lies outside/}, {File.join(dir, "secret.env"), /must be a relative path/} }.each do |file, why|
        File.write(path, "method: code\nemail: { body_file: #{file.inspect} }\n")
        expect_raises(AzookaBay::LoginFile::Error, why) { AzookaBay::LoginFile.load(path, confine: true) }
        AzookaBay::LoginFile.load(path).email_body.not_nil!.should contain "DATABASE_URL" # unconfined: the author's own choice
      end
    end
  end

  it "needs only a method for plain links" do
    in_dir do |dir|
      File.write(File.join(dir, "login.yml"), "method: link\n")
      f = AzookaBay::LoginFile.load(File.join(dir, "login.yml"))
      f.method.should eq "link"
      f.code_style.should be_nil
      f.vocab.should be_nil
      f.email_body.should be_nil
    end
  end

  it "refuses a file of the wrong shape, naming the problem" do
    in_dir do |dir|
      path = File.join(dir, "login.yml")
      File.write(path, "method: code\nlabel: x\nlink_base: https://elsewhere.test\n")
      expect_raises(AzookaBay::LoginFile::Error, /link_base/) { AzookaBay::LoginFile.load(path) }

      File.write(path, "method: code\ncode: { style: vocab, length: 4, vocab: [ka], vocab_file: w.txt }\n")
      expect_raises(AzookaBay::LoginFile::Error, /both vocab and vocab_file/) { AzookaBay::LoginFile.load(path) }

      File.write(path, "method: code\nemail: { body: x, body_file: b.txt }\n")
      expect_raises(AzookaBay::LoginFile::Error, /email has both body and body_file/) { AzookaBay::LoginFile.load(path) }

      File.write(path, "method: code\nfallback_email: { body_file: missing.txt }\n")
      expect_raises(AzookaBay::LoginFile::Error, /cannot read fallback_email.body_file 'missing.txt'/) { AzookaBay::LoginFile.load(path) }

      expect_raises(AzookaBay::LoginFile::Error, /nope.yml/) { AzookaBay::LoginFile.load(File.join(dir, "nope.yml")) }

      File.write(path, "method: code\n---\nmethod: link\n")
      expect_raises(AzookaBay::LoginFile::Error, /one YAML document only/) { AzookaBay::LoginFile.load(path) }
      Dir.mkdir(File.join(dir, "adir"))
      File.write(path, "method: code\nemail: { body_file: adir }\n")
      expect_raises(AzookaBay::LoginFile::Error, /cannot read email.body_file 'adir'/) { AzookaBay::LoginFile.load(path) }

      File.write(path, "method: code\nlabel: one\nlabel: two\n")
      expect_raises(AzookaBay::LoginFile::Error, /duplicate key "label"/) { AzookaBay::LoginFile.load(path) }
      File.write(path, "method: code\nemail: { subject: a, subject: b }\n")
      expect_raises(AzookaBay::LoginFile::Error, /duplicate key "email.subject"/) { AzookaBay::LoginFile.load(path) }
    end
  end
end
