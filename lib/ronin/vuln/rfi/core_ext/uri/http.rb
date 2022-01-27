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

require 'ronin/vuln/rfi/rfi'

module URI
  class HTTP < Generic

    #
    # @see Ronin::Vuln::LFI.scan
    #
    def rfi_scan(options={})
      Ronin::Vuln::RFI.test(self,options)
    end

    #
    # Attempts to find the first RFI vulnerability in the URL.
    #
    # @param [Hash] options
    #   Additional options.
    #
    # @return [Ronin::Vuln::RFI, nil]
    #   The first RFI vulnerability discovered.
    #
    def first_rfi(options={})
      rfi_scan(options).first
    end

    #
    # Determines if the URL is vulnerable to Remote File Inclusion (RFI).
    #
    # @param [Hash] options
    #   Additional options.
    #
    # @return [Boolean]
    #   Specifies whether the URL is vulnerable to RFI.
    #
    def has_rfi?(options={})
      !(first_rfi(options).nil?)
    end

    #
    # @deprecated Use {#rfi_scan} instead.
    #
    def test_rfi(*arguments,&block)
      rfi_scan(*arguments,&block)
    end

    #
    # @deprecated Use {#first_rfi} instead.
    #
    def rfi(*arguments,&block)
      first_rfi(*arguments,&block)
    end

  end
end
