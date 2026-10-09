# Opt-in: `require "azb/login_file"`. Kept out of `require "azb"` so code
# that only signs requests (the Azooka Bay server among it) never links
# libyaml.
require "yaml"
require "../azb"

module AzookaBay
  # A site's login look as files, kept in the product's own repo (by
  # convention `deploy/azb/login.yml`). The YAML names the method and the
  # settings; the vocabulary and the email bodies stay plain-text files
  # beside it. Paths are relative to the YAML file.
  #
  #   method: code
  #   code: { style: vocab, length: 4, vocab_file: magic-words.txt, separator: "-" }
  #   label: Magic Word
  #   email: { subject: "Your Magic Word, mortal", body_file: email-body.txt }
  #   fallback_email: { subject: "The Magic Link, mortal", body_file: fallback-body.txt }
  #
  # `vocab:` and `body:` may be given inline instead of as files (not
  # both). A vocabulary file has one entry per line; blank lines and lines
  # starting with `#` are skipped. Loading checks only the file's shape
  # (strict: an unknown key is an error); Azooka Bay validates the settings
  # themselves when they're applied.
  struct LoginFile
    class Error < Exception; end

    getter method : String
    getter code_style : String?
    getter code_length : Int32?
    getter vocab : Array(String)?
    getter separator : String?
    getter label : String?
    getter email_subject : String?
    getter email_body : String?
    getter fallback_subject : String?
    getter fallback_body : String?

    def initialize(@method, @code_style = nil, @code_length = nil, @vocab = nil, @separator = nil,
                   @label = nil, @email_subject = nil, @email_body = nil,
                   @fallback_subject = nil, @fallback_body = nil)
    end

    # The YAML as written.
    # :nodoc:
    struct Doc
      include YAML::Serializable
      include YAML::Serializable::Strict

      getter method : String
      getter code : CodeDoc? = nil
      getter label : String? = nil
      getter email : EmailDoc? = nil
      getter fallback_email : EmailDoc? = nil
    end

    # :nodoc:
    struct CodeDoc
      include YAML::Serializable
      include YAML::Serializable::Strict

      getter style : String
      getter length : Int32
      getter vocab : Array(String)? = nil
      getter vocab_file : String? = nil
      getter separator : String? = nil
    end

    # :nodoc:
    struct EmailDoc
      include YAML::Serializable
      include YAML::Serializable::Strict

      getter subject : String? = nil
      getter body : String? = nil
      getter body_file : String? = nil
    end

    def self.load(path : String) : LoginFile
      doc = begin
        text = File.read(path)
        unique_keys!(YAML::Nodes.parse(text), path) # YAML lets a repeated key silently win
        Doc.from_yaml(text)
      rescue ex : YAML::ParseException
        raise Error.new("#{path}: #{ex.message}")
      rescue ex : File::Error
        raise Error.new("#{path}: #{ex.message}")
      end
      dir = File.dirname(path)
      code = doc.code
      vocab = code.try { |c| vocab_of(c, dir, path) }
      new(doc.method, code.try(&.style), code.try(&.length), vocab, code.try(&.separator), doc.label,
        doc.email.try(&.subject), doc.email.try { |e| body_of(e, "email", dir, path) },
        doc.fallback_email.try(&.subject), doc.fallback_email.try { |e| body_of(e, "fallback_email", dir, path) })
    end

    private def self.unique_keys!(node : YAML::Nodes::Node, path : String, at : String = "") : Nil
      case node
      when YAML::Nodes::Document, YAML::Nodes::Sequence
        node.nodes.each { |n| unique_keys!(n, path, at) }
      when YAML::Nodes::Mapping
        seen = Set(String).new
        node.nodes.each_slice(2) do |pair|
          k, v = pair[0], pair[1]?
          key = k.is_a?(YAML::Nodes::Scalar) ? k.value : k.to_s
          raise Error.new("#{path}: duplicate key #{(at + key).inspect}") unless seen.add?(key)
          unique_keys!(v, path, "#{at}#{key}.") if v
        end
      end
    end

    private def self.vocab_of(c : CodeDoc, dir : String, path : String) : Array(String)?
      raise Error.new("#{path}: code has both vocab and vocab_file; use one") if c.vocab && c.vocab_file
      if file = c.vocab_file
        read(dir, file, "vocab_file", path).lines.map(&.strip).reject { |l| l.empty? || l.starts_with?('#') }
      else
        c.vocab
      end
    end

    private def self.body_of(e : EmailDoc, key : String, dir : String, path : String) : String?
      raise Error.new("#{path}: #{key} has both body and body_file; use one") if e.body && e.body_file
      if file = e.body_file
        read(dir, file, "#{key}.body_file", path)
      else
        e.body
      end
    end

    private def self.read(dir : String, file : String, key : String, path : String) : String
      File.read(File.expand_path(file, dir))
    rescue ex : File::Error
      raise Error.new("#{path}: cannot read #{key} '#{file}': #{ex.message}")
    end
  end

  class Client
    # Push the login look described by a login file (see LoginFile), for
    # example on every deploy: `client.set_login_file("deploy/azb/login.yml")`.
    # Returns whether anything changed. Raises LoginFile::Error for a file
    # that can't be read or has the wrong shape, and Client::Error (400
    # invalid_login_settings, with the reason) for settings Azooka Bay refuses.
    def set_login_file(path : String) : Bool
      f = LoginFile.load(path)
      set_login(f.method, code_style: f.code_style, code_length: f.code_length, vocab: f.vocab,
        separator: f.separator, label: f.label, email_subject: f.email_subject, email_body: f.email_body,
        fallback_subject: f.fallback_subject, fallback_body: f.fallback_body)
    end
  end
end
