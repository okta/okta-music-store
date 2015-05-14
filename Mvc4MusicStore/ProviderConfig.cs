using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using ComponentSpace.SAML2.Configuration;

namespace Mvc4MusicStore.Okta
{
    public class ProviderConfig
    {
        public string Issuer { get; set; }
        public string SingleSignOnUrl { get; set; }

        public ProviderConfig(string issuer, string singleSignOnUrl)
        {
            this.Issuer = issuer;
            this.SingleSignOnUrl = singleSignOnUrl;
        }

        public PartnerIdentityProviderConfiguration getPartnerIdentityProviderConfiguration(string nickName)
        {
            var config = new PartnerIdentityProviderConfiguration()
            {
                Name = Issuer,
                SingleSignOnServiceUrl = SingleSignOnUrl,
                // This configuration assumes that there will be a .cer file on the filesystem. Which is not ideal!
                // Ideally, this would be configured directly with the "raw" base64 encoded certificate for the IdP
                // (Consider implementing ComponentSpace.SAML2.Data.ICertificateManager to get around this limitation)
                PartnerCertificateFile = String.Format("{0}-idp.cer", nickName),
                SignAuthnRequest = false,
                WantSAMLResponseSigned = false,
                WantAssertionSigned = true,
                WantAssertionEncrypted = false,
            };
            return config;
        }

        public PartnerServiceProviderConfiguration getPartnerServiceProviderConfiguration(string nickName, Uri serverUri)
        {
            var samlAcsPrefix = "saml/acs";
            var appUriBuilder = new UriBuilder(serverUri);
            var path = String.Format("{0}/{1}", samlAcsPrefix, nickName);
            appUriBuilder.Path = path;

            var config = new PartnerServiceProviderConfiguration()
            {
                // LocalCertificateFile = "sp.pfx",
                // LocalCertificatePassword = "password",
                Name = appUriBuilder.Uri.AbsoluteUri,
                AssertionConsumerServiceUrl = String.Format("~{0}", appUriBuilder.Uri.AbsolutePath),
                WantAuthnRequestSigned = false,
                SignSAMLResponse = false,
                SignAssertion = false,
                EncryptAssertion = false,
                DisableInResponseToCheck = false,
            };
            return config;
        }
    }

    public class oktaConfig
    {
        Uri serverUri;
        public Dictionary<string, ProviderConfig> oktaIdpConfigs;

        public oktaConfig(Uri serverUri)
        {
            this.serverUri = serverUri;
            loadConfig();
        }
        /// <summary>
        /// This is just an example! You should implement this for your own environment, using your own datastore.
        /// </summary>
        /// <returns></returns>
        public void loadConfig()
        {
            var configs = new Dictionary<string, ProviderConfig>() {
                // FIXME: This is just an example method, a real implementation will get this from your in-house datastore (SQL or key/value store)
                //
                // IMPORTANT NOTE: This configuration assumes that a file named "{:key}-idp.cer" is in the directory for this solution.
                // For example: The configuration below is named "okta", so we will look for a certificate inside a file named "okta-idp.cer".
                // See the comments in "oktaIdentityProvider.PartnerIdentityProviderConfiguration()" for details about this certificate file configuration.
		// WARNING WARNING WARNING
		// Uncomment the code below for testing purposes.
		// The values below allow you to test using http://saml.oktadev.com
		// Which means that ANYBODY could log in to your server using that tool.
		// WARNING WARNING WARNING
                /*
                {"default", new ProviderConfig(
                    // Identity Provider Issuer:
                    "urn:example:idp",
                    // Identity Provider Single Sign-On URL:
                    "http://idp.oktadev.com")
                }
                */
            };
            this.oktaIdpConfigs = configs;
        }

        public SAMLConfiguration makeComponentSpaceConfig()
        {
            // Create the configuration ComponentSpace.SAML2
            // See also: http://www.componentspace.com/Forums/38/Storing-the-SAML-Configuration-in-a-Database 
            var samlConfiguration = new SAMLConfiguration();
            foreach (var idpName in oktaIdpConfigs.Keys)
            {
                // configure IdP for outbound ("SP initiated") SAML requests
                var partnerIdp = oktaIdpConfigs[idpName].getPartnerIdentityProviderConfiguration(idpName);
                samlConfiguration.AddPartnerIdentityProvider(partnerIdp);

                // configure SP for inbound ("IdP initiated") SAML requests
                var serviceProvider = oktaIdpConfigs[idpName].getPartnerServiceProviderConfiguration(idpName, serverUri);
                samlConfiguration.AddPartnerServiceProvider(serviceProvider);
            }

            // This configures the default SP. Given the configuration we've done already, I'm not sure why this is needed, but it is
            var defaultSpName = "default";
            var defaultConfig = oktaIdpConfigs[defaultSpName].getPartnerServiceProviderConfiguration(defaultSpName, serverUri);
            samlConfiguration.LocalServiceProviderConfiguration = new LocalServiceProviderConfiguration()
            {
                Name = defaultConfig.Name,
                AssertionConsumerServiceUrl = defaultConfig.AssertionConsumerServiceUrl,
            };
            return samlConfiguration;
        }
    }
}