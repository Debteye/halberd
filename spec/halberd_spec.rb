require './lib/halberd'
require 'spec_helper'
describe Halberd::Config do
  class Foo
    include Halberd::Config
  end
  before(:all) do
    @fake = Foo.new
  end
  it "should read from the right location" do
    @fake.config.should_not be_nil
  end

  it "should give us some real credentials" do
    @fake.stub(:config).and_return({'cobrand_id' => 'foo', 'application_id' => "bar", 'cobrand_login' => "baz", 'cobrand_password' => 'woah', 'tnc_version' => 'rargh'})
    @fake.config.each_pair do |k,v|
      @fake.credentials.send(k).should == v
    end
  end
end

describe Halberd::Us do
  before(:each) do 
    @us = Halberd::Us.new
  end

  it "should say it connected correctly to the server if we assume it to be so" do
    receiver = double(:response)
    receiver.stub(:to_hash).and_return({:login_cobrand_response => {:login_cobrand_return => {:cobrand_conversation_credentials => {:session_token => 'foo'}}}})
    @us.client.stub(:request).and_return(receiver)
    @us.connect!
    @us.connected?.should be_true
    @us.session_token.should_not be_nil
    @us.timeout_time.should >= Time.now
  end

  it "should correctly return a You instance with the right us set" do
    @you = @us.spawn 
    @you.us.should == @us
  end

end

describe Halberd::You do
  before(:each) do
    @us = Halberd::Us.new
    @you = @us.spawn
  end

  it "should be able to register if you want to" do
    receiver = double(:response)
    receiver.stub(:to_hash).and_return({:register3_response => {:register3_return => {:user_context => {:conversation_credentials => {:session_token => 'foo'}}}}})
    @you.registration_client.stub(:request).and_return(receiver)

    @you.register!

    @you.logged_in?.should == true
    @you.session_token.should_not be_nil
    @you.timeout_time.should >= Time.now
  end

  it "should be able to login if you want to" do
    receiver = double(:response)
    receiver.stub(:to_hash).and_return({:login2_response => {:login2_return => {:user_context => {:conversation_credentials => {:session_token => 'foo'}}}}})
    @you.login_client.stub(:request).and_return(receiver)

    @you.login!
  
    @you.logged_in?.should == true
    @you.session_token.should_not be_nil
    @you.timeout_time.should >= Time.now
  end

  it "should leave your friends behind" 

end

describe Halberd::You::Items do
  before(:each) do
    @us = Halberd::Us.new
    @you = @us.spawn
    @items = @you.items_interface
  end
  
  it "should be able to register items for content service" do
    content_service_id = 1
    receiver = double(:response)
    receiver.stub(:to_hash).and_return({:add_item_for_content_service1_response => {:add_item_for_content_service1_return => 100}})
    @items.register_client.stub(:request).and_return(receiver)
    @items.items.include?(100).should be_false
    @items.register!(content_service_id, :username => "foo", :password => "bar")
    @items.items.include?(100).should be_true
  end
end
