using ComponentSpace.SAML2.Configuration;
using Mvc4MusicStore.Okta;
using OktaProviders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Web.Security;

namespace Mvc4MusicStore
{
    // Note: For instructions on enabling IIS6 or IIS7 classic mode, 
    // visit http://go.microsoft.com/?LinkId=9394801

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            System.Data.Entity.Database.SetInitializer(new Mvc4MusicStore.Models.SampleData());

            AreaRegistration.RegisterAllAreas();

            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            AuthConfig.RegisterAuth();
        }
        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {
            if (Request.IsAuthenticated)
            {
                string loggedUser = HttpContext.Current.User.Identity.Name;
                var memberUser = (OktaMembershipUser)Membership.GetUser(loggedUser);
                var roles = Roles.GetRolesForUser(loggedUser);
                var identity = new OktaIdentity(memberUser.UserName, true)
                {
                    FirstName = memberUser.FirstName,
                    LastName = memberUser.LastName,
                    PhoneNumber = memberUser.PhoneNumber,
                    Apps = memberUser.apps,
                };
                var principal = new System.Security.Principal.GenericPrincipal(identity, roles);
                HttpContext.Current.User = principal;
            }
        }

        // FIXME: This MUST not be used on a production system. It is only used in this example for the sake of simplicity.
        // I suggest moving "Init_ComponentSpace()" to the Application_Start method 
        // and adding funcitionality to call Init_ComponentSpace whenever your database is updated.
        protected void Application_BeginRequest(Object source, EventArgs e)
        {
            // Run during BeginRequest to get access to the Request object, which simplifies demonstration.
            var thisUrl = HttpContext.Current.Request.Url;
            Init_ComponentSpace(thisUrl);
        }

        protected void Init_ComponentSpace(Uri serverUri)
        {
            // FIXME: This uses a static example configuration.
            // A real production implementation will get this from your in-house datastore (SQL or key/value store)
            var config = new oktaConfig(serverUri);
            var samlConfiguration = config.makeComponentSpaceConfig();
            SAMLConfiguration.Current = samlConfiguration;
        }
    }
}