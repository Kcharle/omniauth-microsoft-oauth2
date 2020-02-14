require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class MicrosoftOauth2 < OmniAuth::Strategies::OAuth2
      AuthUrl = ENV["MICROSOFT_AUTH_URL"] || "https://login.microsoftonline.com"
      Tenant = ENV["MICROSOFT_AUTH_TENANT"] || "common"

      option :name, 'microsoft_oauth2'

      option :client_options, {
        site:          AuthUrl,
        authorize_url: "#{AuthUrl}/#{Tenant}/oauth2/v2.0/authorize_url",
        token_url:     "#{AuthUrl}/#{Tenant}/oauth2/v2.0/token"
      }

      uid do
        access_token.params["user_id"]
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
    end
  end
end
