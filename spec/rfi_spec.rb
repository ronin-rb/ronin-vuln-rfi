require 'spec_helper'
require 'ronin/vuln/rfi'

describe Ronin::Vuln::RFI do
  describe "TEST_SCRIPT" do
    subject { described_class::TEST_SCRIPT }

    it "must be a publically accessible URL", :network do
      response = Net::HTTP.get(URI(subject))

      expect(response.code.to_i).to eq(200)
      expect(response.body).to_not be_empty
    end
  end

  describe ".test_script" do
    subject { described_class }

    it "must have a default test_script URL" do
      expect(subject.test_script).to eq(described_class::TEST_SCRIPT)
    end
  end

  describe ".test_script=" do
    subject { described_class }

    let(:new_url) { 'http://www.example.com/test.php' }

    before do
      subject.test_script = new_url
    end

    it "must set .test_script URL" do
      expect(subject.test_script).to eq(new_url)
    end

    after { subject.test_script = nil }
  end
end
