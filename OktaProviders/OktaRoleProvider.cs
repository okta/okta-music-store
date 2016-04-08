// Install Okta.Core via the "Okta SDK" which is available on NuGet
using Okta.Core;
using Okta.Core.Clients;
using Okta.Core.Models;
using System;
using System.Collections.Generic;
using System.Configuration.Provider; // For the ProviderException thrown by DeleteRole
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Security;
using WebMatrix.WebData;

namespace OktaProviders
{
    /// <summary>
    /// Extends SimpleRoleProvider and redirects all calls into OktaIndependentRoleProvider
    /// </summary>
    public class OktaRoleProvider : SimpleRoleProvider
    {
        private OktaIndependentRoleProvider redirect;
        public OktaRoleProvider()
        {
            redirect = new OktaIndependentRoleProvider();
        }
        public override string[] GetRolesForUser(string username)
        {
            return redirect.GetRolesForUser(username);
        }
        public override void CreateRole(string roleName)
        {
            redirect.CreateRole(roleName);
        }
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            return redirect.DeleteRole(roleName, throwOnPopulatedRole);
        }
        public override string[] GetUsersInRole(string roleName)
        {
            return redirect.GetUsersInRole(roleName);
        }
        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            redirect.AddUsersToRoles(usernames, roleNames);
        }
        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            redirect.RemoveUsersFromRoles(usernames, roleNames);
        }
        public override string[] GetAllRoles()
        {
            return redirect.GetAllRoles();
        }
        public override bool IsUserInRole(string username, string roleName)
        {
            return redirect.IsUserInRole(username, roleName);
        }
        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            return redirect.FindUsersInRole(roleName, usernameToMatch);
        }
        public override bool RoleExists(string roleName)
        {
            return redirect.RoleExists(roleName);
        }
    }

    public class OktaIndependentRoleProvider
    {
        private OktaProviderClient okta;
        public OktaIndependentRoleProvider()
        {
            okta = new OktaProviderClient();
        }
        /// <summary>
        /// Get all Okta groups
        /// </summary>
        /// <returns>A list of Okta Group objects</returns>
        public List<Group> GetAllOktaGroups()
        {
            List<Group> results = new List<Group>();
            PagedResults<Group> groups = okta.groups.GetList();
            foreach (Group oktaGroup in groups.Results)
            {
                results.Add(oktaGroup);
            }
            return results;
        }
        /// <summary>
        /// Turns a string containing a Role Name into a native Okta Group object
        /// </summary>
        /// <param name="groupName">The name of a "role" or group</param>
        /// <returns>Okta Group object</returns>
        public Group GetOktaGroupByRoleName(string groupName)
        {
            Group group = new Group();
            PagedResults<Group> groups = okta.groups.GetList();
            foreach (Group oktaGroup in groups.Results)
            {
                if (oktaGroup.Profile.Name == groupName)
                {
                    group = oktaGroup;
                    break;
                }
                var id = oktaGroup.Id;
            }
            return group;
        }
        public MembershipUser GetUser(string username, bool userIsOnline)
        {
            OktaMembershipUser user = okta.GetOktaMembershipUser(username);
            return user;
        }
        public string[] GetRolesForUser(string username)
        {
            User oktaUser = null;
            try
            {
                oktaUser = okta.users.Get(username);

            }
            catch (OktaException oe)
            {
            //most likely could not find the user because there's more than one user that matches
            }
            if (oktaUser != null)
            {
                var groups = from grp in okta.users.GetUserGroupsClient(oktaUser) select grp.Profile.Name.ToString();
                    return groups.ToArray<string>();
            }
            else
            {
                return null;
            }
        }
        public void CreateRole(string roleName)
        {
            Group oktaGroup = new Group();
            oktaGroup.Profile.Name = roleName;
            okta.groups.Add(oktaGroup);
        }
        public bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            if (throwOnPopulatedRole)
            {
                var usersInGroup = GetUsersInRole(roleName);
                if (usersInGroup.Length != 0)
                {
                    var msg = String.Format("OktaIndependentRoleProvider: Role '{0}' is not empty", roleName);
                    throw new ProviderException(msg);
                }
            }
            try
            {
                var group = GetOktaGroupByRoleName(roleName);
                okta.groups.Remove(group);
                return true;
            }
            catch (OktaException e)
            {
                var reason = e.ErrorSummary;
            }
            return false;
        }
        public string[] GetUsersInRole(string roleName)
        {
            var groupUsersClient = new GroupUsersClient(GetOktaGroupByRoleName(roleName), okta.settings);
            var results = from user in groupUsersClient select user.Profile.Login;
            return results.ToArray<string>();
        }
        public void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            foreach (var roleName in roleNames)
            {
                var oktaGroup = GetOktaGroupByRoleName(roleName);
                var groupUsersClient = new GroupUsersClient(oktaGroup, okta.settings);
                foreach (var username in usernames)
                {
                    var oktaUser = okta.users.Get(username);
                    groupUsersClient.Add(oktaUser);
                }
            }
        }
        public void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            foreach (var roleName in roleNames)
            {
                var oktaGroup = GetOktaGroupByRoleName(roleName);
                var groupUsersClient = new GroupUsersClient(oktaGroup, okta.settings);
                foreach (var username in usernames)
                {
                    var oktaUser = okta.users.Get(username);
                    groupUsersClient.Remove(oktaUser);
                }
            }
        }
        public string[] GetAllRoles()
        {
            var results = from oktaGroup in GetAllOktaGroups() select oktaGroup.Profile.Name;
            return results.ToArray<string>();
        }
        public bool IsUserInRole(string username, string roleName)
        {
            var usersInRole = GetUsersInRole(roleName);
            return usersInRole.Contains(username);
        }
        public string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            var usersFound = new List<string>();
            var users = GetUsersInRole(roleName);
            foreach (var user in users)
            {
                // FIXME: Note that this will not work when usernameToMatch conatins '%' or '_'!
                if (user.Contains(usernameToMatch))
                {
                    usersFound.Add(user);
                }
            }
            return usersFound.ToArray<string>();
        }
        public bool RoleExists(string roleName)
        {
            var group = GetOktaGroupByRoleName(roleName);
            return (group.ObjectClass != null);
        }
    }
}