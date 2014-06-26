require 'net/https'
require 'rexml/document'
require 'logger'

module FreshBooks
  class Connection
    attr_reader :account_url, :consumer_key, :consumer_secret, :token, :token_secret, :utc_offset, :request_headers

    @@logger = Logger.new(STDOUT)
    def logger
      @@logger
    end

    def logger=(value)
      @@logger = value
    end

    def self.log_level=(level)
      @@logger.level = level
    end
    self.log_level = Logger::WARN

    def initialize(account_url, consumer_key, consumer_secret, token, token_secret, request_headers = {}, options = {})
      raise InvalidAccountUrlError.new("account_url is expected to be in the form www.example.com without any protocol string or trailing query parameters") unless account_url =~ /^[0-9a-zA-Z\-_]+\.(freshbooks|billingarm)\.com$/

      @domain = domain
      @consumer_key = consumer_key
      @consumer_secret = consumer_secret
      @token = token
      @token_secret = token_secret
      @request_headers = request_headers
      @utc_offset = options[:utc_offset] || -4
      @start_session_count = 0
    end

    def auth
      data = {
        :realm                  => '',
        :oauth_version          => '1.0',
        :oauth_consumer_key     => @consumer_key,
        :oauth_token            => @token,
        :oauth_timestamp        => timestamp,
        :oauth_nonce            => nonce,
        :oauth_signature_method => 'PLAINTEXT',
        :oauth_signature        => signature,
      }.map { |k,v| %Q[#{k}="#{v}"] }.join(',')

      { 'Authorization' => "OAuth #{data}" }
    end

    def signature
      CGI.escape("#{@consumer_secret}&#{@token_secret}")
    end

    def nonce
      [OpenSSL::Random.random_bytes(10)].pack('m').gsub(/\W/, '')
    end

    def timestamp
      Time.now.to_i
    end

    def call_api(method, elements = [])
      request = create_request(method, elements)
      result = post(request)
      Response.new(result)
    end

    def direct_post(xml)
      result = post(xml)
      Response.new(result)
    end

    def start_session(&block)
      @connection = obtain_connection if @start_session_count == 0
      @start_session_count = @start_session_count + 1

      begin
        block.call(@connection)
      ensure
        @start_session_count = @start_session_count - 1
        close if @start_session_count == 0
      end
    end

  protected

    def create_request(method, elements = [])
      doc = REXML::Document.new '<?xml version="1.0" encoding="UTF-8"?>'
      request = doc.add_element('request')
      request.attributes['method'] = method

      elements.each do |element|
        if element.kind_of?(Hash)
          element = element.to_a
        end
        key = element.first
        value = element.last

        if value.kind_of?(Base)
          request.add_element(REXML::Document.new(value.to_xml))
        else
          request.add_element(REXML::Element.new(key.to_s)).text = value.to_s
        end
      end

      doc.to_s
    end

    def obtain_connection(force = false)
      return @connection if @connection && !force

      @connection = Net::HTTP.new(@account_url, 443)
      @connection.use_ssl = true
      @connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
      @connection.start
    end

    def reconnect
      close
      obtain_connection(true)
    end

    def close
      begin
        @connection.finish if @connection
      rescue => e
        logger.error("Error closing connection: " + e.message)
      end
      @connection = nil
    end

    def post(request_body)
      result = nil
      request = Net::HTTP::Post.new(FreshBooks::SERVICE_URL)
      request.headers auth
      request.body = request_body
      request.content_type = 'application/xml'
      @request_headers.each_pair do |name, value|
        request[name.to_s] = value
      end

      result = post_request(request)

      if logger.debug?
        logger.debug "Request:"
        logger.debug request_body
        logger.debug "Response:"
        logger.debug result.body
      end

      check_for_api_error(result)
    end

    # For connections that take a long time, we catch EOFError's and reconnect seamlessly
    def post_request(request)
      response = nil
      has_reconnected = false
      start_session do |connection|
        begin
          response = connection.request(request)
        rescue EOFError => e
          raise e if has_reconnected

          has_reconnected = true
          connection = reconnect
          retry
        end
      end
      response
    end

    def check_for_api_error(result)
      return result.body if result.kind_of?(Net::HTTPSuccess)

      case result
      when Net::HTTPRedirection
        if result["location"] =~ /loginSearch/
          raise UnknownSystemError.new("Account does not exist")
        elsif result["location"] =~ /deactivated/
          raise AccountDeactivatedError.new("Account is deactivated")
        end
      when Net::HTTPUnauthorized
        raise AuthenticationError.new("Invalid API key.")
      when Net::HTTPBadRequest
        raise ApiAccessNotEnabledError.new("API not enabled.")
      end

      raise InternalError.new("Invalid HTTP code: #{result.class}")
    end
  end
end
