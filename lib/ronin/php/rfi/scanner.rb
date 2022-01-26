#
# ronin-vuln-rfi - A small Ruby library for testing Remote File Inclusion (RFI)
# vulnerabilities.
#
# Copyright (c) 2007-2010 Hal Brodigan (postmodern.mod3 at gmail.com)
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

require 'ronin/php/rfi/rfi'
require 'ronin/scanners/web_vuln_scanner'

module Ronin
  module Scanners
    WebVulnScanner.test_for(:rfi) do |page,block|
      PHP::RFI.scan(page.url,&block)
    end
  end
end
