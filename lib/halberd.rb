require 'savon'
require 'orderedhash'
require 'halberd/utils'

module Halberd 
  
  class Credentials
    attr_accessor :cobrand_id, :application_id, :locale, :tnc_version,
                  :cobrand_login, :cobrand_password
    def initialize
      yield self
    end
  end

  module Config 
    def client_opts
      @client_opts ||= {
        soap_version: 2, 
        log_level: :info,
        log: false, 
        ssl_verify_mode: :none,
        ssl_version: :TLSv1
      }
    end

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

    def preferences
      {
       :currency_code => "USD",
       :time_zone => "CST",
       :date_format => "MM/dd/yyyy",
       :currency_notation_type => "SYMBOL_NOTATION", 
       :number_format => {
         :decimal_separator => ".",
         :grouping_separator => ",", 
         :group_pattern => "###,##0.##"
       }
      }
    end

    def yodlee_location
      config['yodlee_url']
    end 

    def cobrand_client
      url = "#{yodlee_location}/yodsoap/services/CobrandLoginService?wsdl"
      Savon.client(client_opts) do
        endpoint url
        namespace "http://cobrandlogin.login.core.soap.yodlee.com"
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")
      end
    end
  
    def registration_client
      url = "#{yodlee_location}/yodsoap/services/UserRegistrationService?wsdl"
      Savon.client(client_opts) do
        namespace "http://userregistration.usermanagement.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:common' => "http://common.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end

    def login_client
      url = "#{yodlee_location}/yodsoap/services/LoginService?wsdl"
      Savon.client(client_opts) do
        namespace "http://login.login.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:common' => "http://common.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end
 
    def item_client
      url = "#{yodlee_location}/yodsoap/services/ItemManagementService"
      Savon.client(client_opts) do
        namespace "http://itemmanagement.accountmanagement.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:common' => "http://common.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end

    def refresh_client
      url = "#{yodlee_location}/yodsoap/services/RefreshService?wsdl"
      Savon.client(client_opts) do
        namespace "http://refresh.refresh.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:mfarefresh' => 'http://mfarefresh.core.soap.yodlee.com',
                   'xmlns:mfacollections' => 'http://mfarefresh.core.collection.soap.yodlee.com',
                   'xmlns:common' => "http://common.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end
   
    def dataservice_client
      url = "#{yodlee_location}/yodsoap/services/DataService?wsdl"
      Savon.client(client_opts) do
        namespace "http://dataservice.dataservice.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:dataservice' => "http://dataservice.core.soap.yodlee.com",
                   'xmlns:common' => "http://common.soap.yodlee.com",
                   'xmlns:collections' => "http://collections.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end

    def content_traversal_client
      url = "#{yodlee_location}/yodsoap/services/ContentServiceTraversalService"
      Savon.client(client_opts) do
        namespace "http://contentservicetraversal.traversal.ext.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:tns1' => "http://collections.soap.yodlee.com",
                   'xmlns:login' => 'http://login.ext.soap.yodlee.com')
      end
    end
    
    def category_client
      url = "#{yodlee_location}/yodsoap/services/TransactionCategorizationService"
      Savon.client(client_opts) do
        namespace "http://transactioncategorizationservice.transactioncategorization.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:common' => "http://common.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end

    def instant_verification_client
      url = "#{yodlee_location}/yodsoap/services/InstantVerificationDataService"
      Savon.client(client_opts) do
        namespace "http://instantverificationdataservice.verification.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:common' => "http://common.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end

    def extended_instant_verification_client 
      url = "#{yodlee_location}/yodsoap/services/ExtendedInstantVerificationDataService"
      @extended_instant_verification_client ||= Savon::Client.new(client_opts) do
        namespace "http://extendedinstantverificationdataservice.verification.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:tns1' => "http://collections.soap.yodlee.com",
                   'xmlns:login' => 'http://login.ext.soap.yodlee.com',
                   'xmlns:common' => 'http://common.soap.yodlee.com')

      end
    end

    def routing_number_client
      url = "#{yodlee_location}/yodsoap/services/RoutingNumberService"
      Savon.client(client_opts) do
        namespace "http://routingnumberservice.routingnumberservice.core.soap.yodlee.com"
        endpoint url
        namespaces('xmlns:login' => "http://login.ext.soap.yodlee.com",
                   'xmlns:tns1' => "http://collections.soap.yodlee.com")

      end
    end

  end

  

  class Us
    include Config

    attr_accessor :session, :response, :session_token, :channel_id, :timeout_time

    def connect!
       body = {
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
      @response = cobrand_client.call :login_cobrand, message: body
      set_connected_status!
    end
    
    def set_connection(opts = {})
      @session_token = opts[:session_token]
      @channel_id = opts[:channel_id]
      @timeout_time = opts[:timeout_time]
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

      def get_all_content_service_list
          #soap.element_form_default = :unqualified
        body = {
          :cobrandContext => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :preference_info => preferences,
            :fetch_all_locale_data => false,
            :attributes! => {
              :locale => { "xsi:type" => "tns1:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :attributes! => {
            :cobrand_context => { "xsi:type" => "tns1:CobrandContext" }
          }
        }
        @all_ervice_list ||= content_traversal_client.call :get_content_services_by_container_type, message: body 
      end

      def get_all_routing_number_infos
          #soap.element_form_default = :unqualified
        body = {
          :cobrandContext => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :preference_info => preferences,
            :fetch_all_locale_data => false,
            :attributes! => {
              :locale => { "xsi:type" => "tns1:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :attributes! => {
            :cobrand_context => { "xsi:type" => "tns1:CobrandContext" }
          }
        }
        @all_ervice_list ||= routing_number_client.call :get_all_routing_number_infos, message: body
      end

      def get_category_list
        #  soap.element_form_default = :unqualified
        body = {
          :cobrand_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :preference_info => preferences,
            :fetch_all_locale_data => false,
            :attributes! => {
              :locale => { "xsi:type" => "tns1:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            } 
          },
          :order! => [:cobrand_context],
          :attributes! => {
            :cobrand_context => { "xsi:type" => "tns2:CobrandContext" }
          } 
        } 
        @category_list = category_client.call :get_supported_transaction_categrories, message: body
      end

      def get_content_service_info(content_service_id)
        #  soap.element_form_default = :unqualified
        body = {
          :cctx => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :preference_info => preferences,
            :fetch_all_locale_data => false,
            :attributes! => {
              :locale => { "xsi:type" => "tns1:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :content_service_id => content_service_id,
          :req_specifier => (16 | 2 | 1 | 128),
          :order! => [:cctx, :content_service_id, :req_specifier],
          :attributes! => {
            :cobrand_context => { "xsi:type" => "tns1:CobrandContext" }
          }
        }
        @service_list ||= content_traversal_client.call :get_content_service_info1, message: body
      end    

      def get_service_list(container_name)
        #  soap.element_form_default = :unqualified
        body = {
          :cctx => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :preference_info => preferences,
            :fetch_all_locale_data => false,
            :attributes! => {
              :locale => { "xsi:type" => "tns1:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :container_type => container_name,
          :order! => [:cctx, :container_type]
        }
        @service_list ||= content_traversal_client.call :get_content_services_by_container_type2, message: body
      end    

      def get_login_form(content_service_id)
        #  soap.element_form_default = :unqualified
        body = {
          :cobrand_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id,
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token,
            },
            :preference_info => preferences,
            :fetch_all_locale_data => false,
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
        login_form_response = item_client.call :get_login_form_for_content_service, message: body
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
      #  soap.element_form_default = :unqualified
      body = {
        :cobrand_context => {
          :cobrand_id      => credentials.cobrand_id,
          :channel_id      => us.channel_id,
          :locale          => credentials.locale,
          :tnc_version     => credentials.tnc_version,
          :application_id  => credentials.application_id,
          :cobrand_conversation_credentials => {
            :session_token => us.session_token,
          },
          :preference_info => preferences,
          :fetch_all_locale_data => false,
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
      @registration_response = registration_client.call :register3, message: body

      user_registered!
    end

    def user_registered!
      registration_hash = registration_response.to_hash
      @session_token = registration_hash[:register3_response][:register3_return][:user_context][:conversation_credentials][:session_token]
      @timeout_time = Time.now + 7200 if @session_token
    end
  
    def login!
      #  soap.element_form_default = :unqualified
      body = {
        :cobrand_context => {
          :cobrand_id      => credentials.cobrand_id,
          :channel_id      => us.channel_id,
          :locale          => credentials.locale,
          :tnc_version     => credentials.tnc_version,
          :application_id  => credentials.application_id,
          :cobrand_conversation_credentials => {
            :session_token => us.session_token,
          },
          :preference_info => preferences,
          :fetch_all_locale_data => false,
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
      @login_response = login_client.call :login2, message: body
   
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
      ALT_CRED_ORDER   = [:name,
                          :display_name,
                          :is_editable,
                          :is_optional,
                          :is_escaped,
                          :is_optional_mfa,
                          :is_mfa,
                          :default_values,
                          :value,
                          :values,
                          :valid_values,
                          :display_valid_values,
                          :value_identifier, 
                          :value_identifiers, 
                          :value_mask,
                          :value_masks,
                          :field_type,
                          :field_types,
                          :validation_rules,
                          :size,
                          :sizes,
                          :maxlength,
                          :maxlengths,
                          :user_profile_mapping_expressions,
                          :"@xsi:type"]

      def initialize(us, you, opts = {})
        @us = us
        @you = you
        @items = opts[:items] || you.item_ids || []
      end 

      def prefs
        {
         :currency_code => "USD",
         :time_zone => "CST",
         :date_format => "MM/dd/yyyy",
         :currency_notation_type => "SYMBOL_NOTATION", 
         :number_format => {
           :decimal_separator => ".",
           :grouping_separator => ",", 
           :group_pattern => "###,##0.##"
         }
        }
      end

      def get_item_summary_for_item(item_id)
        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_id => item_id,
          :order! => [:user_context, :item_id],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext"}
          }
        }
        @detailed_summary_response = dataservice_client.call :get_item_summary_for_item, message: body
      end

      def update_item_credentials_and_start_verification_data!(item_id, opts = {})
        user_credentials = opts[:credentials]
                   
        user_credentials && user_credentials.map! do |credential|
          CREDENTIAL_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key]
            hsh
          end
        end

#          soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_id => item_id,            
          :credential_fields => {
            :elements => user_credentials,
            :attributes! => {
              :elements => { "xsi:type" => "common:FieldInfoSingle" },
            }
          },                    
          :order! => [:user_context, :item_id, :credential_fields],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }
        update_response = extended_instant_verification_client.call :update_item_credentials_and_start_verification_data_request, message: body

        update_response.to_hash[:update_item_credentials_and_start_verification_data_request_response][:update_item_credentials_and_start_verification_data_request_return]
      end

      def get_instant_account_verification_item!(item_id, opts = {})
        iav_items = [item_id]

        return_items = instant_verification_client.request :sl, :get_item_verification_data do
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
              :fetch_all_locale_data => false,
              :conversation_credentials => {
                :session_token => you.session_token 
              },
              :valid => true,
              :is_password_expired => false,
              :attributes! => {
                :locale => { "xsi:type" => "collections:Locale" },
                :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
                :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
              }
            },
            :item_ids => {
              :elements => iav_items 
            },      
            :order! => [:user_context, :item_ids],
            :attributes! => {
              :user_context => { "xsi:type" => "common:UserContext"}
            }
          }
        end
        
        return_items.to_hash[:get_item_verification_data_response][:get_item_verification_data_return][:elements]
      end

      def register_instant_account_verification!(content_service_id, routing_number, opts = {})
        user_credentials = opts[:credentials]
                   
        user_credentials && user_credentials.map! do |credential|
          CREDENTIAL_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key]
            hsh
          end
        end

        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
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
          :routing_number => routing_number,            
          :order! => [:user_context, :content_service_id, :credential_fields, :routing_number],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }
        @register_response = extended_instant_verification_client.call :add_item_and_start_verification_data_request, message: body
        
        register_response.to_hash[:add_item_and_start_verification_data_request_response][:add_item_and_start_verification_data_request_return]
      end

      def get_detailed_summary!
        #  soap.element_form_default = :unqualified

        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :req => {
                   :global_criteria => nil,
                   :containerCriteria => {:elements => [{:container_type => "bank",
                                                         :data_extent => {:start_level => 0, :end_level => 4}
                                                        },
                                                        {:container_type => "isp",
                                                         :data_extent => {:start_level => 0, :end_level => 16}
                                                        },
                                                        {:container_type => "utilities",
                                                         :data_extent => {:start_level => 0, :end_level => 16}
                                                        },
                                                        {:container_type => "bills",
                                                         :data_extent => {:start_level => 0, :end_level => 16}
                                                        },
                                                        {:container_type => "cable_satellite",
                                                         :data_extent => {:start_level => 0, :end_level => 16}
                                                        },
                                                        {:container_type => "loans",
                                                         :data_extent => {:start_level => 0, :end_level => 16}
                                                        },
                                                        {:container_type => "telephone",
                                                         :data_extent => {:start_level => 0, :end_level => 16}
                                                        },
                                                        {:container_type => "credits",
                                                         :data_extent => {:start_level => 0, :end_level => 4}
                                                        }],
                                          :attributes! => {:elements => {'xsi:type' => 'dataservice:ContainerCriteria'}}
                                         },
                   :history_needed => false,
                   :deleted_item_accounts_needed => false,
                   :include_disabled_items => false,
                   :content_service_info_required => false,
                   :data_service_lite => false,
                   :inactive_item_accounts_needed => false,
                   :include_is_historic_bill_needed => false,
                   :include_shared_accounts => false, 
                   :include_account_additional_info => false,
                   :tax_account_search_criteria => nil,
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
        @detailed_summary_response = dataservice_client.call :get_item_summaries2, message: body
      end

      def get_summary!
        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
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
        @summary_response = dataservice_client.call :get_item_summaries3, message: body
      end

      def put_mfa_request(item_id, opts = {})
        case opts[:type]
        when :token
          user_response_type = "MFATokenResponse"
          user_response = {
            :token => opts[:token]
          }
        when :image
          user_response_type = "MFAImageResponse"
          user_response = {
            :image_string => opts[:image_string]
          }
        else
          user_response_type = "MFAQuesAnsResponse"
          user_response = {
            :ques_ans_detail_array => {
              :elements => opts[:qa].map {|hash| hash.merge(:order! => [:question, :answer, :question_field_type, :answer_field_type])},
              :attributes! => {:elements => {"xsi:type" => "mfarefresh:QuesAndAnswerDetails"}}
            },
            :attributes! => {:ques_ans_detail_array => {"xsi:type" => "mfacollections:ArrayOfQuesAndAnswerDetails"}}
            }
        end
        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :user_response => user_response,
          :item_id => item_id,
          :order! => [:user_context, :user_response,:item_id],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext"},
            :user_response => { "xsi:type" => "mfarefresh:#{user_response_type}" }
          }
        }
        @put_mfa_response = refresh_client.call 'putMFARequest', message: body
      end

      def get_mfa_response(item_id)
        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_id => item_id,
          :order! => [:user_context, :item_id],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext"},
          }
        }
        @refresh_response = refresh_client.call 'getMFAResponse', message: body
      end

      def start_refresh7(item_id, opts = {})
        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_id => item_id,
          :refresh_parameters => {:force_refresh => opts[:force],
                                  :refresh_mode => opts[:mfa] ? "MFA_REFRESH_MODE" : "NORMAL_REFRESH_MODE",
                                  :refresh_priority => 2,
                                  :order! => [:refresh_priority, :force_refresh, :refresh_mode],
                                  :attributes! => {:refresh_mode => {'xsi:type' => 'refresh:RefreshMode'}}
                                 },
          :order! => [:user_context, :item_id, :refresh_parameters],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext"},
            :refresh_parameters => { "xsi:type" => "refresh:RefreshParameters"},
          }
        }
        @refresh_response = refresh_client.call :start_refresh7, message: body
      end

      def start_refresh1(force = false)
       #   soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_ids => {
                        :elements => items 
                       },
          :refresh_priority => 2,
          :force_refresh => force,
          :order! => [:user_context, :item_ids, :refresh_priority, :force_refresh],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext"},
            :item_ids => { "xsi:type" => "collections:ArrayOflong"}
          }
        }
        @refresh_response = refresh_client.call :start_refresh1, message: body
      end

      def get_refresh_info1
        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
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
        @refresh_response = refresh_client.call :get_refresh_info1, message: body
      end

      def get_mfa_questions_and_answers_for_item(item_id)
        #  soap.element_form_default = :unqualified
        body = {
          :user_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id, 
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token
            },
            :preference_info => prefs,
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :mem_item_id => item_id,
          :order! => [:user_context, :mem_item_id],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }
        item = item_client.call :get_mfa_questions_and_answers_for_item, message: body

        item
      end

      def get_login_form_credentials_for_item(item_id)
        #  soap.element_form_default = :unqualified
        body = {
          :user_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id, 
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token
            },
            :preference_info => prefs,
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_id => item_id,
          :order! => [:user_context, :item_id],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }
        item = item_client.call :get_login_form_credentials_for_item, message: body

        item
      end

      def start_verification_data_request1(item_id)
        #  soap.element_form_default = :unqualified
        body = {
          :user_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id, 
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token
            },
            :preference_info => prefs,
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_id => item_id,
          :order! => [:user_context, :item_id],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }
        item_verification = instant_verification_client.call :start_verification_data_request1, message: body

        item_verification
      end

      def instant_account_verification_status
        #  soap.element_form_default = :unqualified
        body = {
          :user_context => {
            :cobrand_id      => credentials.cobrand_id,
            :channel_id      => us.channel_id, 
            :locale          => credentials.locale,
            :tnc_version     => credentials.tnc_version,
            :application_id  => credentials.application_id,
            :cobrand_conversation_credentials => {
              :session_token => us.session_token
            },
            :preference_info => prefs,
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_ids => {
            :elements => items,
          },
          :order! => [:user_context, :item_ids],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
            :item_ids => { "xsi:type" => "collections:ArrayOflong" }
          }
        }
        item_verification = instant_verification_client.call :get_item_verification_data, message: body

        item_verification
      end

      def instant_account_verification_register!(content_service_id, opts = {})
        user_credentials = opts[:credentials]
                   
        user_credentials && user_credentials.map! do |credential|
          CREDENTIAL_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key]
            hsh
          end
        end

        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
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
          :order! => [:user_context, :content_service_id, :credential_fields],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }
        @register_response = instant_verification_client.call :add_item_and_start_verification_data_request1, message: body

        @items << register_response.to_hash[:add_item_and_start_verification_data_request1_response][:add_item_and_start_verification_data_request1_return]
        register_response.to_hash[:add_item_and_start_verification_data_request1_response][:add_item_and_start_verification_data_request1_return]
      end


      def update_credentials(item_id, opts = {})
        user_credentials = opts[:credentials]
        refresh = opts[:refresh].nil? ? true : opts[:refresh]

        user_credentials && user_credentials.map! do |credential|
          CREDENTIAL_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key]
            hsh
          end
        end

        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
            :attributes! => {
              :locale => { "xsi:type" => "collections:Locale" },
              :cobrand_conversation_credentials => { "xsi:type" => "login:SessionCredentials" },
              :conversation_credentials => { "xsi:type" => "login:SessionCredentials" }
            }
          },
          :item_id => item_id,
          :credential_fields => {
            :elements => user_credentials,
            :attributes! => {
              :elements => { "xsi:type" => "common:FieldInfoSingle" },
            }
          },
          :start_refresh_item_on_update => refresh,
          :order! => [:user_context, :item_id, :credential_fields, :start_refresh_item_on_update],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }

        @update_response = item_client.call :update_credentials_for_item1, message: body

        @update_response.to_hash
      end

      def update_credentials_alt(item_id, opts = {})
        user_credentials = opts[:credentials]
        refresh = opts[:refresh].nil? ? true : opts[:refresh]

        user_credentials && user_credentials.map! do |credential|
          ALT_CRED_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key] unless credential[key].nil?
            hsh
          end
        end
 
        #  soap.element_form_default = :unqualified
        xml = Builder::XmlMarkup.new
        xml.instruct!(:xml, encoding: "UTF-8")
        
        xml.userContext("xsi:type" => "common:UserContext") do
          xml.cobrandId(credentials.cobrand_id)
          xml.channelId(us.channel_id)
          xml.locale("xsi:type" => "collections:Locale") do
            credentials.locale.each_pair do |k,v|
              xml.tag!(k,v)
            end
          end
          xml.tncVersion(credentials.tnc_version)
          xml.applicationId(credentials.application_id)
          xml.cobrandConversationCredentials("xsi:type" => "login:SessionCredentials") do
            xml.sessionToken(us.session_token)
          end
          xml.preferenceInfo do 
            prefs.each_pair do |k,v| 
              xml.tag!(k, v)
            end
          end
          xml.conversationCredentials("xsi:type" => "login:SessionCredentials") do
            xml.sessionToken(you.session_token)
          end
          xml.valid(true)
          xml.isPasswordExpired(false)
        end
        
        xml.itemId(item_id)
        xml.credentialFields do
          Halberd::Utils.new.tag_xml(xml, 'elements', user_credentials)
        end 
        
        xml.startRefreshItemOnUpdate(refresh)
  
        @update_response = item_client.call :update_credentials_for_item1, message: xml

        register_response.to_hash[:update_credentials_for_item1_response][:update_credentials_for_item1_return]
      end


      def register!(content_service_id, opts = {})
        user_credentials = opts[:credentials]
        refresh = opts[:refresh].nil? ? true : opts[:refresh]

        user_credentials && user_credentials.map! do |credential|
          CREDENTIAL_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key]
            hsh
          end
        end

        #  soap.element_form_default = :unqualified
        body = {
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
            :fetch_all_locale_data => false,
            :conversation_credentials => {
              :session_token => you.session_token 
            },
            :valid => true,
            :is_password_expired => false,
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
          :start_refresh_item_on_addition => refresh,
          :order! => [:user_context, :content_service_id, :credential_fields, :share_credentials_within_site, :start_refresh_item_on_addition],
          :attributes! => {
            :user_context => { "xsi:type" => "common:UserContext" },
          }
        }

        @register_response = item_client.call :add_item_for_content_service1, message: body

        item_registered!
        register_response.to_hash[:add_item_for_content_service1_response][:add_item_for_content_service1_return]
      end

      def register_alt!(content_service_id, opts = {})
        user_credentials = opts[:credentials]
        refresh = opts[:refresh].nil? ? true : opts[:refresh]

        user_credentials && user_credentials.map! do |credential|
          ALT_CRED_ORDER.inject({}) do |hsh, key|
            hsh[CREDENTIAL_CONVERT[key] || key] = credential[key] unless credential[key].nil?
            hsh
          end
        end
 
        #  soap.element_form_default = :unqualified
        xml = Builder::XmlMarkup.new
        xml.instruct!(:xml, encoding: "UTF-8")
 
        xml.userContext("xsi:type" => "common:UserContext") do
          xml.cobrandId(credentials.cobrand_id)
          xml.channelId(us.channel_id)
          xml.locale("xsi:type" => "collections:Locale") do
            credentials.locale.each_pair do |k,v|
              xml.tag!(k,v)
            end
          end
          xml.tncVersion(credentials.tnc_version)
          xml.applicationId(credentials.application_id)
          xml.cobrandConversationCredentials("xsi:type" => "login:SessionCredentials") do
            xml.sessionToken(us.session_token)
          end
          xml.preferenceInfo do 
            prefs.each_pair do |k,v| 
              xml.tag!(k, v)
            end
          end
          xml.conversationCredentials("xsi:type" => "login:SessionCredentials") do
            xml.sessionToken(you.session_token)
          end
          xml.valid(true)
          xml.isPasswordExpired(false)
        end
        
        xml.contentServiceId(content_service_id)
        xml.credentialFields do
          Halberd::Utils.new.tag_xml(xml, 'elements', user_credentials)
        end 
        
        xml.shareCredentialsWithinSite(true)
        xml.startRefreshItemOnAddition(refresh)
        @register_response = item_client.call :add_item_for_content_service1, message: xml

        item_registered!
        register_response.to_hash[:add_item_for_content_service1_response][:add_item_for_content_service1_return]
      end

      def item_registered!
        @items << register_response.to_hash[:add_item_for_content_service1_response][:add_item_for_content_service1_return]
      end
    end
  end
end
