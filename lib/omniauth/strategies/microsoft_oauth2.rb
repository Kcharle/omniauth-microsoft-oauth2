require 'omniauth-oauth2'
require 'securerandom'

module OmniAuth
  module Strategies
    class MicrosoftOauth2 < OmniAuth::Strategies::OAuth2
      AuthUrl = ENV["MICROSOFT_AUTH_URL"] || "https://login.microsoftonline.com"
      Tenant = ENV["MICROSOFT_AUTH_TENANT"] || "common"

      option :name, 'microsoft_oauth2'

      option :client_options, {
        site:          AuthUrl,
        authorize_url: "#{AuthUrl}/#{Tenant}/oauth2/v2.0/authorize",
        token_url:     "#{AuthUrl}/#{Tenant}/oauth2/v2.0/token"
      }

      uid do
        # Update (Feb. 14, 2020) - Commenting this out as Microsoft Identity Endpoint does not provide this field on the response anymore
        # access_token.params["user_id"]

        # We instead randomize a string temporarily
        SecureRandom.hex
      end

      info do
        { name: uid } # only mandatory field
      end

      extra do
        {}
      end

      # override method in OmniAuth::Strategies::OAuth2 to error
      # when we don't have a client_id or secret:
      def request_phase
        if missing_client_id?
          fail!(:missing_client_id)
        elsif missing_client_secret?
          fail!(:missing_client_secret)
        else
          super
        end
      end

      def missing_client_id?
        [nil, ""].include?(options.client_id)
      end

      def missing_client_secret?
        [nil, ""].include?(options.client_secret)
      end

      # as per https://github.com/omniauth/omniauth-oauth2/issues/93
      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
