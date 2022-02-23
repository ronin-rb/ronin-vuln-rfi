# ronin-vuln-rfi

[![CI](https://github.com/ronin-rb/ronin-vuln-rfi/actions/workflows/ruby.yml/badge.svg)](https://github.com/ronin-rb/ronin-vuln-rfi/actions/workflows/ruby.yml)
[![Code Climate](https://codeclimate.com/github/ronin-rb/ronin-vuln-rfi.svg)](https://codeclimate.com/github/ronin-rb/ronin-vuln-rfi)

* [Website](https://ronin-rb.dev/)
* [Source](https://github.com/ronin-rb/ronin-vuln-rfi)
* [Issues](https://github.com/ronin-rb/ronin-vuln-rfi/issues)
* [Documentation](https://ronin-rb.dev/docs/ronin-vuln-rfi/frames)
* [Slack](https://ronin-rb.slack.com) |
  [Discord](https://discord.gg/6WAb3PsVX9) |
  [Twitter](https://twitter.com/ronin_rb)

## Description

ronin-vuln-rfi is a small Ruby library for testing Remote File Inclusion (RFI)
vulnerabilities

## Features

* Tests URIs for Remote File Inclusion (RFI) vulnerabilities.

## Examples

Test for Remote File Inclusion (RFI):

    require 'ronin/php/rfi'

    url = URI('http://www.example.com/page.php?lang=en')
    url.has_rfi?
    # => true

Get the first viable RFI vulnerability:

    url.first_rfi
    # => #<Ronin::PHP::RFI: ...>

Scan a URL for RFI vulnerabilities:

    url.rfi_scan
    # => [#<Ronin::PHP::RFI: ...>, ...]

## Requirements

* [Ruby] >= 2.7.0

## Install

```shell
$ gem install ronin-vuln-rfi
```

### Gemfile

```ruby
gem 'ronin-vuln-rfi', '~> 0.1'
```

### gemspec

```ruby
gem.add_dependency 'ronin-vuln-rfi', '~> 0.1'
```

## Development

1. [Fork It!](https://github.com/ronin-rb/ronin-vuln-rfi/fork)
2. Clone It!
3. `cd ronin-vuln-rfi/`
4. `bundle install`
5. `git checkout -b my_feature`
6. Code It!
7. `bundle exec rake spec`
8. `git push origin my_feature`

## License

Copyright (c) 2007-2022 Hal Brodigan (postmodern.mod3 at gmail.com)

This file is part of ronin-vuln-rfi.

ronin-vuln-rfi is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ronin-vuln-rfi is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with ronin-vuln-rfi.  If not, see <https://www.gnu.org/licenses/>.

[Ruby]: https://www.ruby-lang.org
