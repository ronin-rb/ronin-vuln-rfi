require 'spec_helper'
require 'ronin/vuln/rfi'

describe Vuln::RFI do
  it "should have a valid TEST_SCRIPT URL" do
    response = Net.http_get(:url => Vuln::RFI::TEST_SCRIPT)

    response.code.to_i.should == 200
    response.body.should_not be_empty
  end

  it "should have a default test_script URL" do
    Vuln::RFI.test_script.should == PHP::RFI::TEST_SCRIPT
  end

  it "should allow configuration of the test_script URL" do
    new_url = 'http://www.example.com/test.php'

    Vuln::RFI.test_script = new_url
    Vuln::RFI.test_script.should == new_url
  end

  after(:all) do
    Vuln::RFI.test_script = nil
  end
end
