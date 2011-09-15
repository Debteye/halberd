require 'savon_model'
require 'orderedhash'

Savon.configure do |config|
  config.soap_version = 2
  config.log_level = :info
  config.log = false
end

module Halberd 
  
  class Credentials
    attr_accessor :cobrand_id, :application_id, :locale, :tnc_version,
      :cobrand_login, :cobrand_password
    def initialize
      yield self
    end
  end

  module Config 
    def config
      config_location = "config/halberd.yml"
      config_location = Rails.root.join(config_location) if defined?(Rails) 
      
      @config ||= YAML.load_file(config_location)
      defined?(Rails) ? @config[Rails.env] : @config
    end 

    def credentials
      @locale ||= OrderedHash.new 
      @locale[:country] = 'US' 
      @locale[:language] = 'en' 

      @credentials ||= Credentials.new do |cr| 
        cr.cobrand_id       = config['credentials']['cobrand_id'] 
        cr.application_id   = config['credentials']['application_id']
        cr.cobrand_login    = config['credentials']['cobrand_login']
        cr.cobrand_password = config['credentials']['cobrand_password']
        cr.locale           = @locale 
        cr.tnc_version      = config['credentials']['tnc_version'] 
      end
    end

    def yodlee_location
      config['yodlee_url']
    end 

    def cobrand_client
      @cobrand_client ||= Savon::Client.new do
        wsdl.namespace = "http://cobrandlogin.login.core.soap.yodlee.com"
        wsdl.endpoint  = "#{yodlee_location}/yodsoap/services/CobrandLoginService"
        http.auth.ssl.verify_mode = :none
      end
    end
  
    def registration_client
      @registration_client ||= Savon::Client.new do
        wsdl.namespace = "http://userregistration.usermanagement.core.soap.yodlee.com"
        wsdl.endpoint  = "#{yodlee_location}/yodsoap/services/UserRegistrationService?wsdl"
        http.auth.ssl.verify_mode = :none
      end
    end

    def login_client
      @login_client ||= Savon::Client.new do
        wsdl.namespace = "http://login.login.core.soap.yodlee.com"
        wsdl.endpoint  = "#{yodlee_location}/yodsoap/services/LoginService?wsdl"
        http.auth.ssl.verify_mode = :none
      end
    end
 
    def item_client
      @item_client ||= Savon::Client.new do
        wsdl.namespace = "http://itemmanagement.accountmanagement.core.soap.yodlee.com"
        wsdl.endpoint  = "#{yodlee_location}/yodsoap/services/ItemManagementService"
        http.auth.ssl.verify_mode = :none
      end
    end
   
    def dataservice_client
      @dataservice_client ||= Savon::Client.new do
        wsdl.namespace = "http://dataservice.dataservice.core.soap.yodlee.com"
        wsdl.endpoint  = "#{yodlee_location}/yodsoap/services/DataService?wsdl"
        http.auth.ssl.verify_mode = :none
      end
    end

    def content_traversal_client
      @content_traversal_client ||= Savon::Client.new do
        wsdl.namespace = "http://contentservicetraversal.traversal.ext.soap.yodlee.com"
        wsdl.endpoint  = "#{yodlee_location}/yodsoap/services/ContentServiceTraversalService"
        http.auth.ssl.verify_mode = :none
      end
    end
    
    def category_client
      @category_client ||= Savon::Client.new do
        wsdl.namespace = "http://transactioncategorizationservice.transactioncategorization.core.soap.yodlee.com"
        wsdl.endpoint  = "#{yodlee_location}/yodsoap/services/TransactionCategorizationService"
        http.auth.ssl.verify_mode = :none
      end
    end

  end

  class Us
    include Config

    attr_accessor :session, :response, :session_token, :channel_id, :timeout_time

    def connect!
      @response = cobrand_client.request :cob, :login_cobrand do
        soap.element_form_default = :unqualified
        soap.namespaces['xmlns:login'] = "http://login.ext.soap.yodlee.com"
        soap.namespaces['xmlns:tns1'] = "http://collections.soap.yodlee.com"
        soap.body = {
          :cobrand_id     => credentials.cobrand_id,
          :application_id => credentials.application_id,
          :locale         => credentials.locale,
          :tnc_version    => credentials.tnc_version,
          :cobrand_credentials => {
            :login_name  => credentials.cobrand_login,
            :password    => credentials.cobrand_password,
            :order!      => [:login_name, :password],
          },
          :order!      => [:cobrand_id, :application_id, :locale, :tnc_version, :cobrand_credentials],
          :attributes! => {
            :cobrand_credentials => {
              "xsi:type" => "login:CobrandPasswordCredentials"
            },
            :locale => { "xsi:type" => "tns1:Locale" }
          }
        }
      end

      set_connected_status!
    end

    def set_connected_status!
      response_hash = response.to_hash
      @session_token = response_hash[:login_cobrand_response][:login_cobrand_return][:cobrand_conversation_credentials][:session_token]
      @channel_id = response_hash[:login_cobrand_response][:login_cobrand_return][:cobrand_conversation_credentials][:channel_id]
      @timeout_time = Time.now + 7200
    end

    def connected?
      !!(timeout_time && timeout_time > Time.now && session_token)
    end

    def spawn
      You.new(self)
    end
   
    def get_interface
      Interface.new(self)
    end

    class Interface
      include Config

      attr_accessor :us
   
      def initialize(us)
        @us = us
      end

      def get_category_list
        @category_list = category_client.request :sl, :get_supported_transaction_categrories do
          soap.element_form_default = :unqualified
          soap.namespaces['xmlns:tns1'] = "http://collections.soap.yodlee.com"
          soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
          soap.body = {
            :cobrandContext => {
              :cobrand_id      => credentials.cobrand_id,
              :channel_id      => us.channel_id,
              :locale          => credentials.locale,
              :tnc_version     => credentials.tnc_version,
              :application_id  => credentials.application_id,
              :cobrand_conversation_credentials => {
                :session_token => us.session_token,
              },
              :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, :cobrand_conversation_credentials],
              :attributes! => {
                :locale => { "xsi:type" => "tns1:Locale" },
                :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
              } 
            },
            :order! => [:cobrandContext],
            :attributes! => {
              :cobrand_context => { "xsi:type" => "tns1:CobrandContext" }
            } 
          } 
        end
      end

      def get_service_list(container_name)
        @service_list ||= content_traversal_client.request :sl, :get_content_services_by_container_type2 do
          soap.element_form_default = :unqualified
          soap.namespaces['xmlns:tns1'] = "http://collections.soap.yodlee.com"
          soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
          soap.body = {
            :cctx => {
              :cobrand_id      => credentials.cobrand_id,
              :channel_id      => us.channel_id,
              :locale          => credentials.locale,
              :tnc_version     => credentials.tnc_version,
              :application_id  => credentials.application_id,
              :cobrand_conversation_credentials => {
                :session_token => us.session_token,
              },
              :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, :cobrand_conversation_credentials],
              :attributes! => {
                :locale => { "xsi:type" => "tns1:Locale" },
                :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
              }
            },
            :container_type => container_name,
            :order! => [:cctx, :container_type],
            :attributes! => {
              :cobrand_context => { "xsi:type" => "tns1:CobrandContext" }
            }
          }
        end
      end    

      def get_login_form(content_service_id)
        login_form_response = item_client.request :sl, :get_login_form_for_content_service do
          soap.element_form_default = :unqualified
          soap.namespaces['xmlns:tns1'] = "http://collections.soap.yodlee.com"
          soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
          soap.body = {
            :cobrand_context => {
              :cobrand_id      => credentials.cobrand_id,
              :channel_id      => us.channel_id,
              :locale          => credentials.locale,
              :tnc_version     => credentials.tnc_version,
              :application_id  => credentials.application_id,
              :cobrand_conversation_credentials => {
                :session_token => us.session_token,
              },
              :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, :cobrand_conversation_credentials],
              :attributes! => {
                :locale => { "xsi:type" => "tns1:Locale" },
                :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
              }
            },
            :content_service_id => content_service_id,
            :order! => [:cobrand_context, :content_service_id],
            :attributes! => {
              :cobrand_context => { "xsi:type" => "tns1:CobrandContext" }
            }
          }
        end
      end
    end
  end

  class You
    include Config

    attr_accessor :us, :username, :password, :item_ids, :registration_response, 
                  :login_response, :session_token, :timeout_time

    def initialize(us, opts = {})
      @us = us
      @username = opts[:username]
      @password = opts[:password]
      @item_ids = opts[:item_ids]
    end

    def register!
      @registration_response = registration_client.request :user_reg, :register3 do
        soap.element_form_default = :unqualified
        soap.namespaces['xmlns:tns1'] = "http://collections.soap.yodlee.com"
        soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
        soap.namespaces['xmlns:common'] = "http://common.soap.yodlee.com"
        soap.body = {
          :cobrand_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, :cobrand_conversation_credentials],
            :attributes! => {
              :locale => { "xsi:type" => "tns1:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :user_credentials => {
            :login_name => username,
            :password => password,
            :order! => [:login_name, :password]
          },
          :user_profile => { :values => { :table => {
            :key => 'EMAIL_ADDRESS',
            :value => "support+#{username}@debteye.com",
            :attributes! => {
              :key => { "xsi:type" => "xsd:string" },
              :value => { "xsi:type" => "xsd:string" }
            }
          } } },
          :order! => [:cobrand_context, :user_credentials, :user_profile],
          :attributes! => {
            :cobrand_context => { "xsi:type" => "tns1:CobrandContext" },
            :user_credentials => { "xsi:type" => "login:PasswordCredentials" }
          }
        }
      end

      user_registered!
    end

    def user_registered!
      registration_hash = registration_response.to_hash
      @session_token = registration_hash[:register3_response][:register3_return][:user_context][:conversation_credentials][:session_token]
      @timeout_time = Time.now + 7200 if @session_token
    end
  
    def login!
      @login_response = login_client.request :user_reg, :login2 do
        soap.element_form_default = :unqualified
        soap.namespaces['xmlns:tns1'] = "http://collections.soap.yodlee.com"
        soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
        soap.namespaces['xmlns:common'] = "http://common.soap.yodlee.com"
        soap.body = {
          :cobrand_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, :cobrand_conversation_credentials],
            :attributes! => {
              :locale => { "xsi:type" => "tns1:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :user_credentials => {
            :login_name => username,
            :password => password,
            :order! => [:login_name, :password]
          },
          :order! => [:cobrand_context, :user_credentials],
          :attributes! => {
            :cobrand_context => { "xsi:type" => "tns1:CobrandContext" },
            :user_credentials => { "xsi:type" => "login:PasswordCredentials" }
          }
        }
      end
   
      user_logged_in!
    end

    def user_logged_in!
      login_hash = login_response.to_hash
      @session_token = login_hash[:login2_response][:login2_return][:user_context][:conversation_credentials][:session_token]
      @timeout_time = Time.now + 7200 if @session_token
    end
   
    def logged_in?
      return !!(session_token && timeout_time > Time.now)
    end

    def items_interface
      @items_interface ||= Items.new(us, self)
    end

    class Items
      include Config

      attr_accessor :us, :you, :items, :register_response, :summary_response

      CREDENTIAL_CONVERT = {:is_optional_mfa => "isOptionalMFA", 
                            :is_mfa => "isMFA"}
      CREDENTIAL_ORDER = [:name,
                          :display_name,
                          :is_editable,
                          :is_optional,
                          :is_escaped,
                          :is_optional_mfa,
                          :is_mfa,
                          :value,
                          :value_identifier,
                          :value_mask,
                          :field_type,
                          :size,
                          :maxlength]

      def initialize(us, you, opts = {})
        @us = us
        @you = you
        @items = opts[:items] || you.item_ids || []
      end 

      def prefs
        prefs = OrderedHash.new

        prefs['currencyCode'] = 'USD'
        prefs['timeZone'] = 'CST'
        prefs['dateFormat'] = 'MM/dd/yyyy'
        prefs['currencyNotationType'] = 'SYMBOL_NOTATION'
        prefs
      end

      def get_detailed_summary!
        @detailed_summary_response = dataservice_client.request :lines, :get_item_summaries2 do
          soap.element_form_default = :unqualified
          soap.namespaces['xmlns:collections'] = "http://collections.soap.yodlee.com"
          soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
          soap.namespaces['xmlns:common'] = 'http://common.soap.yodlee.com'
          soap.namespaces['xmlns:dataservice'] = "http://dataservice.core.soap.yodlee.com"
          soap.body = {
            :user_context => {
              :cobrand_id      => credentials.cobrand_id,
              :channel_id      => us.channel_id,
              :locale          => credentials.locale,
              :tnc_version     => credentials.tnc_version,
              :application_id  => credentials.application_id,
              :cobrand_conversation_credentials => {
                :session_token => us.session_token,
              },
              :preference_info => prefs,
              :conversation_credentials => {
                :session_token => you.session_token 
              },
              :valid => true,
              :is_password_expired => false,
              :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, 
                          :cobrand_conversation_credentials, :preference_info, 
                          :conversation_credentials, :valid, :is_password_expired],
              :attributes! => {
                :locale => { "xsi:type" => "collections:Locale" },
                :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
                :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
              }
            },
            :req => {
                     :containerCriteria => {:elements => [{:container_type => "bank",
                                                           :data_extent => {:start_level => 0, :end_level => 4}
                                                          }],
                                            :attributes! => {:elements => {'xsi:type' => 'dataservice:ContainerCriteria'}}
                                           },
                     :history_needed => true,
                     :deleted_item_accounts_needed => false,
                     :include_disabled_items => false,
                     :content_service_info_required => false,
                     :data_service_lite => false,
                     :inactive_item_accounts_needed => false,
                     :include_is_historic_bill_needed => false,
                     :include_shared_accounts => false,
                     :attributes! => { :containerCriteria => {"xsi:type" => "collections:List" }}
                    },
            :item_ids => {
                          :elements => items 
                         },
            :order! => [:user_context, :req, :item_ids],
            :attributes! => {
              :user_context => { "xsi:type" => "common:UserContext"},
              :item_ids => { "xsi:type" => "collections:ArrayOflong"}
            }
          }
        end
      end

      def get_summary!
        @summary_response = dataservice_client.request :lines, :get_item_summaries3 do
          soap.element_form_default = :unqualified
          soap.namespaces['xmlns:collections'] = "http://collections.soap.yodlee.com"
          soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
          soap.namespaces['xmlns:common'] = 'http://common.soap.yodlee.com'
          soap.body = {
            :user_context => {
              :cobrand_id      => credentials.cobrand_id,
              :channel_id      => us.channel_id,
              :locale          => credentials.locale,
              :tnc_version     => credentials.tnc_version,
              :application_id  => credentials.application_id,
              :cobrand_conversation_credentials => {
                :session_token => us.session_token,
              },
              :preference_info => prefs,
              :conversation_credentials => {
                :session_token => you.session_token 
              },
              :valid => true,
              :is_password_expired => false,
              :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, 
                          :cobrand_conversation_credentials, :preference_info, 
                          :conversation_credentials, :valid, :is_password_expired],
              :attributes! => {
                :locale => { "xsi:type" => "collections:Locale" },
                :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
                :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
              }
            },
            :item_ids => {
                          :elements => items 
                         },
            :order! => [:user_context, :item_ids],
            :attributes! => {
              :user_context => { "xsi:type" => "common:UserContext"},
              :item_ids => { "xsi:type" => "collections:ArrayOflong"}
            }
          }
        end
      end

      def register!(content_service_id, opts = {})
        user_credentials = opts[:credentials]

        user_credentials && user_credentials.map! do |credential|
          CREDENTIAL_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key]
            hsh
          end
        end

        @register_response = item_client.request :sl, :add_item_for_content_service1 do
          soap.element_form_default = :unqualified
          soap.namespaces['xmlns:tns1'] = "http://collections.soap.yodlee.com"
          soap.namespaces['xmlns:login'] = 'http://login.ext.soap.yodlee.com'
          soap.namespaces['xmlns:common'] = 'http://common.soap.yodlee.com'
          soap.body = {
            :user_context => {
              :cobrand_id      => credentials.cobrand_id,
              :channel_id      => us.channel_id,
              :locale          => credentials.locale,
              :tnc_version     => credentials.tnc_version,
              :application_id  => credentials.application_id,
              :cobrand_conversation_credentials => {
                :session_token => us.session_token,
              },
              :preference_info => prefs,
              :conversation_credentials => {
                :session_token => you.session_token 
              },
              :valid => true,
              :is_password_expired => false,
              :order! => [:cobrand_id, :channel_id, :locale, :tnc_version, :application_id, 
                          :cobrand_conversation_credentials, :preference_info, 
                          :conversation_credentials, :valid, :is_password_expired],
              :attributes! => {
                :locale => { "xsi:type" => "collections:Locale" },
                :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
                :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
              }
            },
            :content_service_id => content_service_id,
            :credential_fields => {
              :elements => user_credentials,
              :attributes! => {
                :elements => { "xsi:type" => "common:FieldInfoSingle" },
              }
            },
            :share_credentials_within_site => true,
            :start_refresh_item_on_addition => true,
            :order! => [:user_context, :content_service_id, :credential_fields, :share_credentials_within_site, :start_refresh_item_on_addition],
            :attributes! => {
              :user_context => { "xsi:type" => "common:UserContext" },
            }
          }
        end

        item_registered!
        register_response.to_hash[:add_item_for_content_service1_response][:add_item_for_content_service1_return]
      end

      def item_registered!
        @items << register_response.to_hash[:add_item_for_content_service1_response][:add_item_for_content_service1_return]
      end
    end
  end
end
