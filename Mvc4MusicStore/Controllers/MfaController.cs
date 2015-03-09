using Mvc4MusicStore.Models;
using Okta.Core;
using Okta.Core.Models;
using OktaProviders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace Mvc4MusicStore.Controllers
{
    public class MfaController : Controller
    {
        private OktaProviderClient okta;
        private string oktaResponseKey = "oktaResponse";

        private Factor pickFactor(List<Factor> factors, string factorType)
        {
            foreach (var factor in factors)
            {
                if (factor.FactorType == factorType)
                {
                    return factor;
                }
            }
            return null;
        }

        public MfaController()
        {
            okta = new OktaProviderClient();
        }

        // GET: /Mfa/
        public ActionResult Index()
        {
            return View();
        }

        // GET: /Mfa/Add
        public ActionResult Add()
        {
            var response = (AuthResponse)Session[oktaResponseKey];
            var status = okta.authn.GetStatus(response.StateToken);
            var factors = status.Embedded.Factors;

            // If we only have one option, just render the enrollment page for that directly
            if (factors.Count == 1)
            {
                var factorType = factors[0].FactorType;
                var redirectTo = String.Format("/Mfa/Enroll?factorType={0}", factorType);
                return Redirect(redirectTo);
            }
            // Otherwise, give the user a dropdown
            return View(factors);
        }

        // GET: /Mfa/Enroll?factorType={string}
        public ActionResult Enroll(string factorType)
        {
            var response = (AuthResponse)Session[oktaResponseKey];
            var stateToken = response.StateToken;
            var status = okta.authn.GetStatus(stateToken);
            // FIXME: Allow the user to select the page they want to see
            var factor = pickFactor(status.Embedded.Factors, factorType);
            if (factor != null)
            {
                var enrollment = okta.authn.Enroll(stateToken, factor);
                if (enrollment.Embedded.Factor.FactorType == "token:software:totp")
                {
                    var factorActivation = enrollment.Embedded.Factor.Embedded.Activation;
                    ViewBag.SharedSecret = factorActivation.SharedSecret;
                    ViewBag.QRCode = factorActivation.Links["qrcode"];
                }
                ViewBag.FactorType = enrollment.Embedded.Factor.FactorType;
                return View();
            }
            return View();
        }

        // POST: /Mfa/Enroll
        [HttpPost]
        public ActionResult Enroll(Otp otp, string factorType)
        {
            if (ModelState.IsValid != true)
            {
                return View();
            }
            var response = (AuthResponse)Session[oktaResponseKey];
            var stateToken = response.StateToken;
            response = okta.authn.GetStatus(stateToken);
            try
            {
                var rv = okta.authn.ActivateTotpFactor(stateToken, response, otp.passCode);
                return CreateSessionFor(rv);
            }
            catch
            {
                return View();
            }
        }

        // GET: /Mfa/Verify
        public ActionResult Verify()
        {
            var response = (AuthResponse)Session[oktaResponseKey];
            var factor = response.Embedded.Factors.First();
            ViewBag.FactorType = factor.FactorType;
            return View();
        }

        private ActionResult CreateSessionFor(AuthResponse response)
        {
            if (response.Status != AuthStatus.Success)
            {
                throw new Exception("Unexpected error when validating MFA");
            }
            var username = response.Embedded.User.Profile.Login;
            var createPersistentCookie = true;
            FormsAuthentication.SetAuthCookie(username, createPersistentCookie);
            // Store the most recent response in the session
            Session[oktaResponseKey] = response;
            return RedirectToAction("CompleteMfa", "Account");
        }

        // POST: /Mfa/Verify
        [HttpPost]
        public ActionResult Verify(Otp otp)
        {
            if (ModelState.IsValid != true)
            {
                return View();
            }
            var response = (AuthResponse)Session[oktaResponseKey];
            var factor = response.Embedded.Factors.First();
            ViewBag.FactorType = factor.FactorType;
            var answer = new MfaAnswer();
            answer.Passcode = otp.passCode;
            // TODO: Modify "response" to get the _links for the .factors attribute, then pass the factor from factors to Verify()
            try
            {
                var rv = okta.authn.Verify(response.StateToken, factor, answer);
                return CreateSessionFor(rv);
            }
            catch (OktaException e)
            {
                ModelState.AddModelError("*", e.ErrorSummary);
            }
            return View();
        }
    }
}
