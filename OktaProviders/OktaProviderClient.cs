// Install Okta.Core via the "Okta SDK" which is available on NuGet
using Okta.Core;
using Okta.Core.Clients;
using Okta.Core.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security;

namespace OktaProviders
{
    public class OktaIdentity : IIdentity
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string DisplayName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public IEnumerable<OktaAppLink> Apps { get; set; }

        private bool _isAuthenticated;
        private string _login;


        public string AuthenticationType
        {
            get { return "OKTA"; }
        }

        public bool IsAuthenticated
        {
            get { return _isAuthenticated; }
        }

        public string Name
        {
            get { return _login; }
        }

        public OktaIdentity(string login, bool isAuthenticated)
        {
            _login = login;
            _isAuthenticated = isAuthenticated;
        }
    }

    public class OktaAppLink
    {
        public string appName { get; set; }
        public string label { get; set; }
        public Uri linkUrl { get; set; }
        public Uri logoUrl { get; set; }

        public OktaAppLink(AppLink input)
        {
            appName = input.AppName;
            label = input.Label;
            linkUrl = input.LinkUrl;
            logoUrl = input.LogoUrl;
        }
    }
    public class OktaMembershipUser : MembershipUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PhoneNumber { get; set; }
        public IEnumerable<OktaAppLink> apps { get; set; }

        public OktaMembershipUser(
            string providerName,
            string name,
            object providerUserKey,
            string email,
            string passwordQuestion,
            string comment,
            bool isApproved,
            bool isLockedOut,
            DateTime creationDate,
            DateTime lastLoginDate,
            DateTime lastActivityDate,
            DateTime lastPasswordChangedDate,
            DateTime lastLockoutDate
        )
            : base(
              providerName,
              name,
              providerUserKey,
              email,
              passwordQuestion,
              comment,
              isApproved,
              isLockedOut,
              creationDate,
              lastLoginDate,
              lastActivityDate,
              lastPasswordChangedDate,
              lastLockoutDate) { }
    }

    public class OktaProviderClient
    {
        public OktaSettings settings { get; set; }
        public OktaClient client { get; set; }
        public UsersClient users { get; set; }
        public GroupsClient groups { get; set; }
        public SessionsClient sessions { get; set; }
        public AppsClient apps { get; set; }
        public AuthClient authn { get; set; }
        public OrgFactorsClient factors { get; set; }

        private void Setup(string apiToken, Uri baseUri)
        {
            settings = new OktaSettings();
            settings.ApiToken = apiToken;
            settings.BaseUri = baseUri;

            client = new OktaClient(settings);
            users = client.GetUsersClient();
            groups = client.GetGroupsClient();
            sessions = client.GetSessionsClient();
            apps = client.GetAppsClient();
            authn = new AuthClient(settings);
            factors = new OrgFactorsClient(settings);
        }

        public OktaProviderClient()
        {
            var apiToken = ConfigurationManager.AppSettings["okta:ApiToken"];
            var baseUri = new System.Uri(ConfigurationManager.AppSettings["okta:ApiUrl"]);
            Setup(apiToken, baseUri);
        }

        public OktaProviderClient(string apiToken, Uri baseUri)
        {
            Setup(apiToken, baseUri);
        }

        public OktaMembershipUser GetOktaMembershipUser(string username)
        {
            User oktaUser;
            try
            {
                oktaUser = users.Get(username);
            }
            catch (OktaException e)
            {
                // "Not found."
                if (e.ErrorCode == "E0000007")
                {
                    return null;
                }
                throw e;
            }
            return OktaUserToOktaMembershipUser(oktaUser);
        }
        public OktaMembershipUser GetOktaMembershipUser(User oktaUser, bool populateApps = true)
        {
            return OktaUserToOktaMembershipUser(oktaUser, populateApps);
        }
        public OktaMembershipUser OktaUserToOktaMembershipUser(User oktaUser, bool populateApps = true)
        {
            bool isApproved = false;
            bool isLockedOut = false;
            var status = oktaUser.Status;
            if (status == "ACTIVE")
            {
                isApproved = true;
            }
            if (status == "PASSWORD_EXPIRED" | status == "LOCKED_OUT" | status == "RECOVERY")
            {
                isLockedOut = true;
            }
            DateTime lastLockoutDate = new DateTime(1754, 1, 1);
            string passwordQuestion = "";
            if (oktaUser.Credentials.RecoveryQuestion.Answer != null)
            {
                passwordQuestion = oktaUser.Credentials.RecoveryQuestion.Answer;
            }
            OktaMembershipUser user = new OktaMembershipUser(
                Membership.Provider.Name.ToString(),
                oktaUser.Profile.Login,
                oktaUser.Id,
                oktaUser.Profile.Email,
                passwordQuestion,
                "", // "comment" - Okta doesn't have this concept by default
                isApproved,
                isLockedOut,
                oktaUser.Created,
                oktaUser.LastLogin,
                oktaUser.LastUpdated,
                oktaUser.PasswordChanged,
                lastLockoutDate
                );

            if(!populateApps) {
                return user;
            }

            var userAppLinks = users.GetUserAppLinksClient(oktaUser);
            var appLinks = userAppLinks.ToList<AppLink>();
            user.apps = from link in appLinks select new OktaAppLink(link);

            user.FirstName = oktaUser.Profile.FirstName;
            user.LastName = oktaUser.Profile.LastName;
            user.PhoneNumber = oktaUser.Profile.MobilePhone;

            return user;
        }
    }
}
