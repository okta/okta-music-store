// Install Okta.Core via the "Okta SDK" which is available on NuGet
using Okta.Core;
using Okta.Core.Clients;
using Okta.Core.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web.Security;
using System.Web;
using WebMatrix.WebData;

namespace OktaProviders
{
    /// <summary>
    /// An extension of the SimpleMembershipProvider class which uses an Okta instance to manage the user lifecycle.
    /// </summary>
    public class OktaMembershipProvider : SimpleMembershipProvider
    {
        private OktaProviderClient okta;

        public OktaMembershipProvider()
        {
            okta = new OktaProviderClient();
        }
        /// <summary>
        /// Creates a new user account with the profile data in the "values" dictionary.
        /// 
        /// See also: http://msdn.microsoft.com/en-us/library/gg537973%28v=vs.111%29.aspx
        /// </summary>
        /// <param name="userName">The user name</param>
        /// <param name="userPassword">The password</param>
        /// <param name="requireConfirmation">(Unused) Specify that the user account must be confirmed</param>
        /// <param name="values">A dictonary that should contain the keys "FirstName", "LastName", and "PhoneNumber"</param>
        /// <returns>
        /// (Unused) Always returns "". Intended to be used to return a token that could be sent to the user to confirm the user account. 
        /// </returns>
        public override string CreateUserAndAccount(string userName, string userPassword, bool requireConfirmation, IDictionary<string, object> values)
        {
            var userProfile = new User(
                userName, // Login
                userName, // Email
                values["FirstName"].ToString(),  // FirstName
                values["LastName"].ToString(),  // LastName
                values["PhoneNumber"].ToString() // MobilePhone
                );
            // FIXME: This could be made simpler?
            userProfile.Credentials = new LoginCredentials();
            userProfile.Credentials.Password.Value = userPassword;

            try
            {
                var createdUser = okta.users.Add(userProfile);
                return "";
            }
            catch (OktaException oktaException)
            {
                string errorSummary = oktaException.ErrorCauses[0].ErrorSummary;
                var status = MembershipCreateStatus.UserRejected;
                if (errorSummary.StartsWith("login: An object with this field already exists"))
                {
                    status = MembershipCreateStatus.DuplicateUserName;
                }
                else if (errorSummary.StartsWith("Passwords must have at least"))
                {
                    status = MembershipCreateStatus.InvalidPassword;
                }
                throw new MembershipCreateUserException(status);
            }
        }
        /// <summary>
        /// Creates a new user account using the specified user name and account by calling 
        /// <see cref=">OktaMembershipProvider.CreateUserAndAccount"/> with a dictionary containing empty values.
        /// 
        /// See also: http://msdn.microsoft.com/en-us/library/gg538405%28v=vs.111%29.aspx
        /// </summary>
        /// <param name="userName">The user name</param>
        /// <param name="userPassword">The password</param>
        /// <param name="requireConfirmationToken">(Unused) Specify that the user account must be confirmed</param>
        /// <returns>
        /// (Unused) Always returns "". Intended to be used to return a token that could be sent to the user to confirm the user account.
        /// </returns>
        public override string CreateAccount(string userName, string userPassword, bool requireConfirmationToken)
        {
            var values = new Dictionary<string, object>();
            values.Add("FirstName", "Unknown");
            values.Add("LastName", "Unknown");
            values.Add("PhoneNumber", "408-555-1212");

            return CreateUserAndAccount(userName, userPassword, requireConfirmationToken, values);
        }

        // The following methods are not implemented since they are not used by the MVC Music Store: 
        // - CreateUser
        // - GetUser(object providerUserKey, bool userIsOnline)

        /// <summary>
        /// Returns a MembershipUser object representation of the user identified by "username".
        /// 
        /// See also: http://msdn.microsoft.com/en-us/library/gg538376%28v=vs.111%29.aspx
        /// </summary>
        /// <param name="username">The user name to return the user object for</param>
        /// <param name="userIsOnline">(Unused) Intended to be used to signal that the "last-activity" timestamp for the user should be updated.</param>
        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            OktaMembershipUser user = okta.GetOktaMembershipUser(username);
            return user;
        }
        /// <summary>
        /// Validates that the specified username and password exist by attempting to create an Okta session for that username and password.
        /// If the username and password are valid, a "CookieToken" is stored in the "HttpContext.Current.Items" dictonary.
        /// To log the user into Okta and enable automatic authentication against federated websites, 
        /// this CookieToken must be used as part of the URL in the "Location" header in an HTTP 302 "Moved Temporarily" HTTP response.
        /// 
        /// See also: 
        /// http://msdn.microsoft.com/en-us/library/webmatrix.webdata.simplemembershipprovider.validateuser%28v=vs.111%29.aspx
        /// http://developer.okta.com/docs/examples/session_cookie.html
        /// </summary>
        /// <param name="username">The username to validate</param>
        /// <param name="password">The password to validate</param>
        /// <returns><c>true</c> if the username and password are validated by Okta. <c>false</c> otherwise.</returns>
        public override bool ValidateUser(string username, string password)
        {
            try
            {
                string relayState = (string)HttpContext.Current.Items["relayState"];
                // Let Okta track the relayState as part of the user's session
                AuthResponse response = okta.authn.Authenticate(username, password, relayState);

                if(response.Status == AuthStatus.Success)
                {
                    HttpContext.Current.Items["login"] = response.Embedded.User.Profile.Login;
                }

                HttpContext.Current.Items[username] = response;

                if (response.Status == AuthStatus.Success)
                {
                    return true;
                }
            }
            catch (OktaException e)
            {
                var reason = e.ErrorSummary;
                HttpContext.Current.Items["authnError"] = reason;
            }
            return false;
        }
        /// <summary>
        /// Deactivates the user account identified by <c>username</c>.
        /// 
        /// See also: http://msdn.microsoft.com/en-us/library/webmatrix.webdata.simplemembershipprovider.deleteaccount%28v=vs.111%29.aspx
        /// </summary>
        /// <param name="username">The user name of the account to deactivate.</param>
        /// <returns><c>true</c> if the account deactivation is successful. <c>false</c> otherwise.</returns>
        public override bool DeleteAccount(string username)
        {
            var user = GetUser(username, false);
            if (user == null)
            {
                return false;
            }
            try
            {
                okta.users.Deactivate(user.ProviderUserKey.ToString());
                return true;
            }
            catch (OktaException e)
            {
                var reason = e.ErrorSummary;
            }
            return false;
        }
        /// <summary>
        /// Change the password of the user identified by <c>username</c> and <c>oldPassword</c> to <c>newPassword</c>.
        /// 
        /// NOTE: Passwords can only be changed on accounts with a status of "ACTIVE".
        /// 
        /// See also: http://msdn.microsoft.com/en-us/library/webmatrix.webdata.simplemembershipprovider.changepassword%28v=vs.111%29.aspx
        /// </summary>
        /// <param name="username">The user name.</param>
        /// <param name="oldPassword">The current password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns><c>true</c> if the password change is successful. <c>false</c> otherwise.</returns>
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            var oktaUser = okta.users.Get(username);
            try
            {
                var rv = okta.users.ChangePassword(oktaUser, oldPassword, newPassword);
                return true;
            }
            catch (OktaException e)
            {
                var reason = e.ErrorSummary;
            }
            return false;
        }
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            var oktaUsers = okta.users.GetList();
            var result = new MembershipUserCollection();
            var records = 0;
            foreach (var oktaUser in oktaUsers.Results)
            {
                var user = okta.GetOktaMembershipUser(oktaUser, false);
                records++;
                result.Add(user);
            }
            totalRecords = records;
            return result;
            // return base.GetAllUsers(pageIndex, pageSize, out totalRecords);
        }
    }
}