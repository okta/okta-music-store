using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Mvc4MusicStore.Models;
using Mvc4MusicStore.Filters;
using System.Web.Security;

namespace Mvc4MusicStore.Controllers
{
    // [Authorize(Roles = "StoreManager")]
    public class GroupManagerController : Controller
    {
        private string designator = "brand:";
        private IEnumerable<string> GroupsList()
        {
            var roleList = Roles.GetAllRoles();
            var groups = from foo in roleList where foo.StartsWith(designator) select foo.Split(':')[1];
            return groups;
        }
        private string RealGroupName(string formatted)
        {
            return String.Format("{0}{1}", designator, formatted);
        }
        //
        // GET: /GroupManager/

        public ActionResult Index()
        {
            var groups = GroupsList();
            return View(groups);
        }

        //
        // GET: /GroupManager/Create

        public ActionResult Create()
        {
            return View();
        }

        //
        // POST: /GroupManager/Create

        [HttpPost]
        public ActionResult Create(UserGroup group)
        {
            try
            {
                string name = RealGroupName(group.Name);
                Roles.CreateRole(name);
                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        // GET: //GroupManager/Details/Foo
        public ActionResult Details(string groupName)
        {
            string name = RealGroupName(groupName);
            string[] users = Roles.GetUsersInRole(name);
            ViewBag.GroupName = groupName;
            return View(users);
        }

        // GET: /GroupManager/Edit/Foo
        public ActionResult Edit(string groupName)
        {
            // Not implemented: http://stackoverflow.com/a/281935/3191847
            return RedirectToAction("Index");
        }

        // POST: /GroupManager/Edit/Foo
        [HttpPost]
        public ActionResult Edit(string groupName, UserGroup group)
        {
            // Not implemented: http://stackoverflow.com/a/281935/3191847
            return RedirectToAction("Index");
        }

        //
        // GET: /GroupManager/Delete/Foo

        public ActionResult Delete(string groupName)
        {
            string name = RealGroupName(groupName);
            Roles.DeleteRole(name);
            return RedirectToAction("Index");
        }

        // FIXME: Annotate here that this should also be implemented in an ideal world
        // POST: /GroupManager/Delete/Foo

        [HttpPost]
        public ActionResult Delete(string groupName, UserGroup group)
        {
            try
            {
                // TODO: Add delete logic here

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }
    }
}
