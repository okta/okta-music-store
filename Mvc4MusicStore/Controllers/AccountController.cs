using System;
using System.Collections.Generic;
using System.Linq;
using System.Transactions;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using DotNetOpenAuth.AspNet;
using Microsoft.Web.WebPages.OAuth;
using WebMatrix.WebData;
using Mvc4MusicStore.Filters;
using Mvc4MusicStore.Models;
using OktaProviders;
using System.Configuration;
using Okta.Core.Models;
using System.Web.Helpers;

namespace Mvc4MusicStore.Controllers
{
    [Authorize]
    [InitializeSimpleMembership]
    public class AccountController : Controller
    {
        private string oktaResponseKey = "oktaResponse";

        private void MigrateShoppingCart(string UserName)
        {
            // Associate shopping cart items with logged-in user
            var cart = ShoppingCart.GetCart(this.HttpContext);

            cart.MigrateCart(UserName);
            Session[ShoppingCart.CartSessionKey] = UserName;
        }
        private ActionResult RedirectToOktaOrHome()
        {
            var UserName = HttpContext.User.Identity.Name;
            return RedirectToOktaOrHome(UserName);
        }
        private ActionResult RedirectToOktaOrHome(string UserName)
        {
            var redirectUrl = this.Url.Action("Index", "Home", null, this.Request.Url.Scheme);
            string cookieTokenUrl = null;
            AuthResponse response = null;

            if (Session[oktaResponseKey] != null)
            {
                response = (AuthResponse)Session[oktaResponseKey];
            }

            if (response.RelayState != null)
            {
                redirectUrl = response.RelayState;
            }

            if (response.SessionToken != null)
            {
                var cookieToken = response.SessionToken;
                var oktaApiUrl = new Uri(ConfigurationManager.AppSettings["okta:ApiUrl"]);
                cookieTokenUrl = String.Format("{0}login/sessionCookieRedirect?token={1}&redirectUrl={2}",
                    oktaApiUrl.AbsoluteUri,
                    cookieToken,
                    HttpUtility.UrlEncode(redirectUrl));
            }

            if(cookieTokenUrl != null)
            {
                // If we have a cookieTokenUrl, redirect the user to Okta so that they get a cookie from Okta too.
                return Redirect(cookieTokenUrl);
            }
            else
            {
                return Redirect(redirectUrl);
            }
        }

        //
        // GET: /Account/Login

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login

        private string ProcessOktaRelayState(System.Collections.Specialized.NameValueCollection form)
        {
            var relayStateStr = "RelayState";
            if (form[relayStateStr] == null)
            {
                return null;
            }
            var relayState = HttpUtility.UrlDecode(form[relayStateStr]);
            if (relayState.StartsWith("//"))
            {
                // Delete the first "/" from the string:
                // Remove "1" character from the string, starting at position "0"
                relayState = relayState.Remove(0, 1);
            }
            // Use http://example.com because UriBuilder needs a scheme and domain to work
            var url = String.Format("http://example.com{0}", relayState);
            var uri = new System.UriBuilder(url);
            var qs = HttpUtility.ParseQueryString(uri.Query);
            uri.Query = null;
            if (qs.Get(relayStateStr) != null)
            {
                uri.Query = String.Format("{0}={1}", relayStateStr, qs.Get(relayStateStr));
            }
            var relayStateClean = String.Join("", uri.Path, uri.Query);
            return relayStateClean;
        }


        [HttpPost]
        [AllowAnonymous]
        public ActionResult Login(LoginModel model, string returnUrl)
        {
            try
            {
                AntiForgery.Validate();
            }
            catch (HttpAntiForgeryException)
            {
                var relayState = ProcessOktaRelayState(Request.Form);
                if (relayState == null)
                {
                    return View(model);
                }
                Session["RelayState"] = relayState;
                return View(model);
            }

            // Immediately return if we have an invalid ModelState
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "The user name or password provided is incorrect.");
                return View(model);
            }


            #region if we have a returnUrl, turn it into an absolute URL
            if (returnUrl != null)
            {
                var uri = new System.UriBuilder(HttpContext.Request.Url.AbsoluteUri);
                if(returnUrl.Contains('?'))
                {
                    var parts = returnUrl.Split('?');
                    uri.Path = parts[0];
                    // FIXME: That this has the entire query string in it.
                    uri.Query = parts[1];
                }
                else
                {
                    uri.Path = returnUrl;
                    uri.Query = null;
                }
                returnUrl = uri.ToString();
            }
            #endregion
            // Store the relayState in the HttpContext to "pass" it to the OktaMembershipProvider
            if (Session["RelayState"] != null)
            {
                returnUrl = (string)Session["RelayState"];
            }
            if (returnUrl != null)
            {
                HttpContext.Items["relayState"] = returnUrl;
            }
            var userValid = WebSecurity.Login(model.UserName, model.Password, persistCookie: model.RememberMe);
            AuthResponse response = null;
            if (HttpContext.Items.Contains(model.UserName))
            {
                response = (AuthResponse)HttpContext.Items[model.UserName];
                Session[oktaResponseKey] = response;

            }

            // See if the username/password pair was valid.
            // This will be "false" if there is an MFA step, so we will check for that next.
            if (userValid)
            {
                MigrateShoppingCart(model.UserName);

                return RedirectToOktaOrHome(model.UserName);
            }
            else if (response != null && response.Status != null)
            {
                if (response.Status == AuthStatus.MfaEnroll)
                {
                    return RedirectToLocal("/Mfa/Add");
                }
                else if (response.Status == AuthStatus.MfaRequired)
                {
                    return RedirectToLocal("/Mfa/Verify");
                }
                else if (response.Status == AuthStatus.PasswordExpired)
                {
                    return RedirectToLocal("/Account/PasswordExpired");
                }
                else if (response.Status == AuthStatus.PasswordReset)
                {
                    //  /Account/PasswordReset
                }
            }
            else if (HttpContext.Items.Contains("authnError"))
            {
                var reason = (string)HttpContext.Items["authnError"];
                ModelState.AddModelError("", reason);
                return View(model);
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Error logging in.");
            return View(model);
        }

        // GET: /Account/CompleteMfa
        public ActionResult CompleteMfa()
        {
            return RedirectToOktaOrHome();
        }

        //
        // POST: /Account/LogOff

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            WebSecurity.Logout();

            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/Register

        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                // Attempt to register the user
                try
                {
                    WebSecurity.CreateUserAndAccount(model.UserName, model.Password, model);
                    WebSecurity.Login(model.UserName, model.Password);
                    MigrateShoppingCart(model.UserName);
                    return RedirectToOktaOrHome(model.UserName);
                }
                catch (MembershipCreateUserException e)
                {
                    ModelState.AddModelError("", ErrorCodeToString(e.StatusCode));
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // POST: /Account/Disassociate

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Disassociate(string provider, string providerUserId)
        {
            string ownerAccount = OAuthWebSecurity.GetUserName(provider, providerUserId);
            ManageMessageId? message = null;

            // Only disassociate the account if the currently logged in user is the owner
            if (ownerAccount == User.Identity.Name)
            {
                // Use a transaction to prevent the user from deleting their last login credential
                using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.Serializable }))
                {
                    bool hasLocalAccount = true; // OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
                    if (hasLocalAccount || OAuthWebSecurity.GetAccountsFromUserName(User.Identity.Name).Count > 1)
                    {
                        OAuthWebSecurity.DeleteAccount(provider, providerUserId);
                        scope.Complete();
                        message = ManageMessageId.RemoveLoginSuccess;
                    }
                }
            }

            return RedirectToAction("Manage", new { Message = message });
        }

        //
        // GET: /Account/Manage

        public ActionResult Manage(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : "";
            ViewBag.HasLocalPassword = true; // OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            ViewBag.ReturnUrl = Url.Action("Manage");
            return View();
        }

        //
        // POST: /Account/Manage

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Manage(LocalPasswordModel model)
        {
            bool hasLocalAccount = true; // OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            ViewBag.HasLocalPassword = hasLocalAccount;
            ViewBag.ReturnUrl = Url.Action("Manage");
            if (hasLocalAccount)
            {
                if (ModelState.IsValid)
                {
                    // ChangePassword will throw an exception rather than return false in certain failure scenarios.
                    bool changePasswordSucceeded;
                    try
                    {
                        changePasswordSucceeded = WebSecurity.ChangePassword(User.Identity.Name, model.OldPassword, model.NewPassword);
                    }
                    catch (Exception)
                    {
                        changePasswordSucceeded = false;
                    }

                    if (changePasswordSucceeded)
                    {
                        return RedirectToAction("Manage", new { Message = ManageMessageId.ChangePasswordSuccess });
                    }
                    else
                    {
                        ModelState.AddModelError("", "The current password is incorrect or the new password is invalid.");
                    }
                }
            }
            else
            {
                // User does not have a local password so remove any validation errors caused by a missing
                // OldPassword field
                ModelState state = ModelState["OldPassword"];
                if (state != null)
                {
                    state.Errors.Clear();
                }

                if (ModelState.IsValid)
                {
                    try
                    {
                        WebSecurity.CreateAccount(User.Identity.Name, model.NewPassword);
                        return RedirectToAction("Manage", new { Message = ManageMessageId.SetPasswordSuccess });
                    }
                    catch (Exception)
                    {
                        ModelState.AddModelError("", String.Format("Unable to create local account. An account with the name \"{0}\" may already exist.", User.Identity.Name));
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // POST: /Account/ExternalLogin

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            return new ExternalLoginResult(provider, Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/ExternalLoginCallback

        [AllowAnonymous]
        public ActionResult ExternalLoginCallback(string returnUrl)
        {
            AuthenticationResult result = OAuthWebSecurity.VerifyAuthentication(Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
            if (!result.IsSuccessful)
            {
                return RedirectToAction("ExternalLoginFailure");
            }

            if (OAuthWebSecurity.Login(result.Provider, result.ProviderUserId, createPersistentCookie: false))
            {
                return RedirectToLocal(returnUrl);
            }

            if (User.Identity.IsAuthenticated)
            {
                // If the current user is logged in add the new account
                OAuthWebSecurity.CreateOrUpdateAccount(result.Provider, result.ProviderUserId, User.Identity.Name);
                return RedirectToLocal(returnUrl);
            }
            else
            {
                // User is new, ask for their desired membership name
                string loginData = OAuthWebSecurity.SerializeProviderUserId(result.Provider, result.ProviderUserId);
                ViewBag.ProviderDisplayName = OAuthWebSecurity.GetOAuthClientData(result.Provider).DisplayName;
                ViewBag.ReturnUrl = returnUrl;
                return View("ExternalLoginConfirmation", new RegisterExternalLoginModel { UserName = result.UserName, ExternalLoginData = loginData });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLoginConfirmation(RegisterExternalLoginModel model, string returnUrl)
        {
            string provider = null;
            string providerUserId = null;

            if (User.Identity.IsAuthenticated || !OAuthWebSecurity.TryDeserializeProviderUserId(model.ExternalLoginData, out provider, out providerUserId))
            {
                return RedirectToAction("Manage");
            }

            if (ModelState.IsValid)
            {
                // Insert a new user into the database
                using (UsersContext db = new UsersContext())
                {
                    Models.UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == model.UserName.ToLower());
                    // Check if user already exists
                    if (user == null)
                    {
                        // Insert name into the profile table
                        db.UserProfiles.Add(new Models.UserProfile { UserName = model.UserName });
                        db.SaveChanges();

                        OAuthWebSecurity.CreateOrUpdateAccount(provider, providerUserId, model.UserName);
                        OAuthWebSecurity.Login(provider, providerUserId, createPersistentCookie: false);

                        return RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        ModelState.AddModelError("UserName", "User name already exists. Please enter a different user name.");
                    }
                }
            }

            ViewBag.ProviderDisplayName = OAuthWebSecurity.GetOAuthClientData(provider).DisplayName;
            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // GET: /Account/ExternalLoginFailure

        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        [AllowAnonymous]
        [ChildActionOnly]
        public ActionResult ExternalLoginsList(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return PartialView("_ExternalLoginsListPartial", OAuthWebSecurity.RegisteredClientData);
        }

        [ChildActionOnly]
        public ActionResult RemoveExternalLogins()
        {
            ICollection<OAuthAccount> accounts = OAuthWebSecurity.GetAccountsFromUserName(User.Identity.Name);
            List<ExternalLogin> externalLogins = new List<ExternalLogin>();
            foreach (OAuthAccount account in accounts)
            {
                AuthenticationClientData clientData = OAuthWebSecurity.GetOAuthClientData(account.Provider);

                externalLogins.Add(new ExternalLogin
                {
                    Provider = account.Provider,
                    ProviderDisplayName = clientData.DisplayName,
                    ProviderUserId = account.ProviderUserId,
                });
            }

            ViewBag.ShowRemoveButton = externalLogins.Count > 1; // || OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            return PartialView("_RemoveExternalLoginsPartial", externalLogins);
        }

        #region Helpers
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
        }

        internal class ExternalLoginResult : ActionResult
        {
            public ExternalLoginResult(string provider, string returnUrl)
            {
                Provider = provider;
                ReturnUrl = returnUrl;
            }

            public string Provider { get; private set; }
            public string ReturnUrl { get; private set; }

            public override void ExecuteResult(ControllerContext context)
            {
                OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
            }
        }

        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
        #endregion
    }
}
