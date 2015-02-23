using Mvc4MusicStore.Filters;
using Mvc4MusicStore.Models;
using OktaProviders;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using WebMatrix.WebData;

namespace Mvc4MusicStore.Controllers
{
    [Authorize(Roles = "StoreManager")]
    [InitializeSimpleMembership]
    public class UserManagerController : Controller
    {
        private string designator = "brand:";
        private string managerRoleName = "StoreManager";

        private IEnumerable<string> GroupsList()
        {
            var roleList = Roles.GetAllRoles();
            var groups = from foo in roleList where foo.StartsWith(designator) select foo.Split(':')[1];
            return groups;
        }
        private string GroupNameToRoleName(string groupName)
        {
            return String.Join("", designator, groupName);
        }
        private string RoleNameToGroupName(string roleName)
        {
            return roleName.Split(':')[1];
        }
        private StoreUser StoreUserFromUsername(string username)
        {
            var storeUser = new StoreUser();
            storeUser.userName = username;
            foreach (var role in Roles.GetRolesForUser(username))
            {
                if (role.StartsWith(designator))
                {
                    storeUser.recordLabel = RoleNameToGroupName(role);
                } 
                else if(role == managerRoleName)
                {
                    storeUser.isManager = true;
                }
            }
            return storeUser;
        }
        //
        // GET: /UserManager/
        public ActionResult Index()
        {
            var membershipUsers = Membership.GetAllUsers();
            var userList = from MembershipUser user in membershipUsers select user.Email.ToString();
            return View(userList);
        }

        //
        // GET: /UserManager/Details/5

        public ActionResult Details(int id)
        {
            return View();
        }

        //
        // GET: /UserManager/Create

        public ActionResult Create()
        {
            return View();
        }

        //
        // POST: /UserManager/Create

        [HttpPost]
        public ActionResult Create(FormCollection collection)
        {
            try
            {
                // TODO: Add insert logic here

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        //
        // GET: /UserManager/Edit/5

        public ActionResult Edit(string username)
        {
            var storeUser = StoreUserFromUsername(username);
            ViewBag.RecordLabel = new SelectList(GroupsList(), storeUser.recordLabel);
            return View(storeUser);
        }

        //
        // POST: /UserManager/Edit/5

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(StoreUser storeUserNew)
        {
            if (ModelState.IsValid)
            {
                var give = new List<string>();
                var take = new List<string>();

                var storeUserOld = StoreUserFromUsername(storeUserNew.userName);
                if(storeUserOld.recordLabel != storeUserNew.recordLabel)
                {
                    if (storeUserOld.recordLabel != null)
                    {
                        take.Add(GroupNameToRoleName(storeUserOld.recordLabel));
                    }
                    if(storeUserNew.recordLabel != null)
                    {
                        give.Add(GroupNameToRoleName(storeUserNew.recordLabel));
                    }
                }
                if(storeUserOld.isManager != storeUserNew.isManager)
                {
                    if(storeUserNew.isManager)
                    {
                        give.Add(managerRoleName);
                    }
                    else
                    {
                        take.Add(managerRoleName);
                    }
                }

                string[] takeRoles = take.ToArray();
                string[] giveRoles = give.ToArray();

                if(takeRoles.Length > 0)
                {
                    Roles.RemoveUserFromRoles(storeUserNew.userName, takeRoles);
                }
                if(giveRoles.Length > 0)
                {
                    Roles.AddUserToRoles(storeUserNew.userName, giveRoles);
                }
                return RedirectToAction("Index");
            }
            ViewBag.RecordLabel = new SelectList(GroupsList(), storeUserNew.recordLabel);
            return View(storeUserNew);
        }

        //
        // GET: /UserManager/Delete/5

        public ActionResult Delete(string username)
        {
            ((SimpleMembershipProvider)Membership.Provider).DeleteAccount(username);
            ((SimpleMembershipProvider)Membership.Provider).DeleteUser(username, true);

            return RedirectToAction("Index");
        }

        //
        // POST: /UserManager/Delete/5

        [HttpPost]
        public ActionResult Delete(string username, FormCollection collection)
        {
            return Delete(username);
        }
    }
}
