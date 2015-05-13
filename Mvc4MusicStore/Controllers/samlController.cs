using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Configuration;
using Mvc4MusicStore.Okta;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;


namespace Example_SAML_SP.Controllers
{
    public class samlController : Controller
    {
        //
        // GET: /saml/
        public ActionResult Index()
        {
            return View();
        }

        // This handles "SP initiated" login
        // GET: /saml/login/:id
        public ActionResult login(string id)
        {
            var idpName = id;

            string relayState = null;
            var config = new oktaConfig(HttpContext.Request.Url);
            var partnerIdP = config.oktaIdpConfigs[id].Issuer;
            try
            {
                SAMLServiceProvider.InitiateSSO(Response, relayState, partnerIdP);
            }
            catch (ComponentSpace.SAML2.Exceptions.SAMLException exception)
            {
                // Exceptions that you might want to catch and handle yourself include:
                // - SAMLSchemaValidationException
                // - SAMLSignatureException
                throw exception;
            }

            // We should never get here, the InitiateSSO method should redirect the user as approprate.
            return new EmptyResult();
        }

        // This handles "IdP initiated" login
        // GET: /saml/acs/:id
        [HttpPost]
        public ActionResult acs(string id)
        {
            var idpName = id;

            // See also: C:\Program Files (x86)\ComponentSpace SAML v2.0 for .NET\Examples\SSO\HighLevelAPI\MVC\MvcExampleServiceProvider\Controllers
            bool isInResponseTo = false;
            string partnerIdP = null;
            string userName = null;
            IDictionary<string, string> attributes = null;
            string targetUrl = null;

            // Receive and process the SAML assertion contained in the SAML response.
            // The SAML response is received either as part of IdP-initiated or SP-initiated SSO.
            try
            {
                SAMLServiceProvider.ReceiveSSO(Request, out isInResponseTo, out partnerIdP, out userName, out attributes, out targetUrl);
            }
            catch (ComponentSpace.SAML2.Exceptions.SAMLException exception)
            {
                // Exceptions that you might want to catch and handle yourself include:
                // - SAMLSchemaValidationException
                // - SAMLSignatureException
                throw exception;
            }

            var createPersistentCookie = true;
            FormsAuthentication.SetAuthCookie(userName, createPersistentCookie);

            var redirectUrl = this.Url.Action("Index", "Home", null, this.Request.Url.Scheme);

            var relayState = Request.Form["RelayState"];
            if (relayState != null)
            {
                redirectUrl = relayState;
            }
            if (redirectUrl == "")
            {
                redirectUrl = "/";
            }
            return Redirect(redirectUrl);

        }
    }
}
