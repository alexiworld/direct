<style>
r { color: Red }
o { color: Orange }
g { color: Green }
s { text-decoration: none; color: Teal; }
</style>

Design modern oriented architecture for organization management. the system will be called direct. direct will allow super admins to sign up their organizations.

# <r>FUNCTIONAL REQUIREMENTS</r>

## <s>ORGANIZATION</s>
- when creating the organization, the system will capture organization name, contact information and address. 
- the organizations will have organization units, groups, users, roles, and permissions. organization unit is hierarchical in structure. 
- when organization is created, the system will automatically create an organization unit with the same name, contact information and address as the organization, and super admin added to the organization unit. 
- organizations are isolated from each other and in the beginning will not share any data or access.   

## <s>USERS</s>
- users will be added to the organization by invitation
- when inviting an user, the system must capture their first and last name, email address, phone number for contact. 
- additional attributes can be added later during the design and development.

## <s>ORGANIZAGION UNIT</s>
- the organization unit will have name, description, address. 
- one user can only be invited/added to one organization unit
- one user can be moved from one to another organization unit thus keeping the rule the user to remain only in one organization unit.
- super admins are always members of the top org unit. assigning a super admin role to an user will require to move them in the top org unit first and then granting them the super admin role. moving a user to the top level org unit alone does not make them super admins.
- the person who creates the org unit becomes owner of that org unit and any sub org units that may be created.
- the org unit owner is allowed to create or remove sub org units.
- the org unit owner can move sub org units within their own org units.
- the user cannot remove the org unit they are member of.
- org units are used to model the hierarchical structure of an organization, for example in a big organization a head office is the root (means the same as top level) org unit, any subsidiaries can be org units on the second level, departments within subsidiaries can be org units on the third level, sub departments or teams can be modeled as org units on the fourth or fifth level. 
- org units are used for user management including user details, direct reports, possibly time and other type of approvals or user management activities.
- org units are not used for role management (in the context of what system or custom roles and permissions are used for).
  
# <s>GROUPS</s> 
- Likewise, the moment organization is created a dummy "root" group will be created. The owner of this "root" group will be the super admin. The group will have ADMIN role assigned to it. Any user added to this group will have ADMIN permissions.
- Groups, unlike org units, are used for role management. 
- A group can be assigned a role with permissions. 
- Any member of the group automatically by business rule, implicitly inherit the role(s) assigned to a group or their subgroups.  
- DB records will show the user membership in a group but only roles directly (explicitly) assigned to the user themselves will be recorded. Any implicit roles (aka roles by business rule) will be calculated at runtime by traversing the groups assigned to the user and compiling the list of inherited roles by the rule of group membership.
- Group management is a powerful way to define custom permissions and roles, and assign them to user and groups thus extending the capabilities of the system to include any other resources (e.g. devices, products, things, etc.) in the future.

## <s>ROLES</s> 
- a role is a collection of permissions
- there are predifined roles, which list of permissions is strictly set and can be changed at system level (DB or API script, system API). these predifined roles can be called system roles. they can be initialized by running DB migration scripts. system roles cannot be changed from users of the system. 
- there are custom roles, which are defined by name but identified by internal guid. the role names can be unique within the organization but it is not unique across multiple organizations. the same role name can be created and found in two different organizations and it may represent two different roles with different list of permissions.
- roles are organization specific and do not apply to other organizations.
- the system roles will be SUPER_ADMIN, OU_OWNER, OU_MANAGER, OU_MEMBER, GROUP_CREATE, GROUP_OWNER, GROUP_MANAGER, GROUP_MEMBER
- SUPER_ADMIN will be the ultimate role granting all access. A person with this role does not need to have any other role. By having this role super admins will be considered having all defined, undefined, and future roles and permissions.
- A person with SUPER_ADMIN role can grant any role to any user within the super admin organization.
- OU_OWNER will be organization unit owner role. When granting OU_OWNER role to a person, the role is bound to a specific org unit and do not apply to other org units with the exception being the sub org units. A person having this role can : 
  - create organization units, 
  - can move sub organization units between their org units (for example OU A > OU B and OU A > OU C represent org unit A with childred/subs OU B and OU C, and the owner can change it to OU A > OU B > OU C converting OU C a sub org unit for OU B. the other way is also possible, org unit owner can change OU A > OU B > OU C to OU A > OU B and OU A > OU C), 
  - can invite user to organization unit, 
  - can remove user from organization unit, 
  - can move user between their own org unit, 
  - can grant OU_OWNER role (for any of their own org units) to another user, 
  - can revoke OU_OWNER role (for any of their own org units) from another user, 
  - can grant OU_MANAGER role (for any of their own org units) to another user, 
  - can revoke OU_MANAGER role (for any of their own org units) from another user
- OU_OWNER role is for specific organization unit. A person with this role appears as organization unit owner (thus having all permissions specific to this role) for any sub organization unit. If the person has created or has been granted OU_OWNER role for OU A, and OU A has two (direct or indirect) sub org units, the same person will behave as OU_OWNER for the sub org units even if they are not granted explicit OU_OWNER and related role permissions to the sub org units.    
- OU_MANAGER will be organization unit manager role. When granting OU_MANAGER role to a person, the role is bound to a specific org unit and do not apply to other org units, not even to sub org units. A person having this role can : 
  - can invite user to organization unit, 
  - can edit user details, 
  - cannot remove user from the organization unit,
  - cannot move users out the organization unit to another org unit,
  - does not have OU_MANAGER for sub org units unless it has been explicitly granted by another user with OU_OWNER permissions for the sub org unit.  
- OU_MEMBER role for specific org unit is granted to every user when being added to the org unit. OU_MEMBER role is revoked when removing the user from the org unit. when transferring user from one org unit to another org unit, their OU_MEMBER role is updated/remapped to the new org and does no longer apply to their old org unit. A person having this role can:
  - see other members of the same org unit they are member of, this includes viewing other members information (first and last name, email and phone number) 
  - see sub org units of their own org units
  - see sub org units' user details
  - cannot invite or delete users to their own org unit, nor to any of the sub org units.
- GROUP_CREATE role can be assigned by default to any user     
- GROUP_OWNER role is assigned to user who created a group. A person with this role can:
  - invite other users granting them GROUP_MEMBER role for that specific group,
  - remove users from the group, effectively revoking their GROUP_MEMBER role for that specific group, 
  - promote group members by granting them GROUP_OWNER or GROUP_MANAGER role for that same group in addition to users' existing GROUP_MEMBER role,
  - demote group members by revoking any of GROUP_OWNER or GROUP_MANAGER roles for that same group, 
  - or create sub groups,
  - act as a group owner for any sub groups even if no explicit GROUP_OWNER role is granted for the sub groups,
  - view group members, user details, and sub groups and their members. 
- GROUP_MANAGER role is assigned to an existing user of a group. A person with this role can:
  - invite other users granting them GROUP_MEMBER role for that specific group, 
  - promote group members by granting them GROUP_MANAGER role for that same group in addition to users' existing GROUP_MEMBER role, 
  - view group members, user details, and sub groups and their members.
- GROUP_MEMBER role is assigned to an user when adding them to the group. As result the group member's roles will be a collection of user own roles (a.k.a. user direct roles) and user indirect roles (assumed by being a member of the group). User indirect roles include not only roles assigned to the group (the user is member of) but also any roles assigned to the subgroups.
- every user will have GROUP_CREATE and OU_MEMBER roles assigned by default.
- every user cannot grant higher roles or permissions than the ones they posses to other users.

### SUPER_ADMIN permissions
Does not need permissions to be defined. It allows any operations. Super admin can assign the same privileges to some other user but that user must be first moved to the top level org unit. Another name for the top level org unit would be root org unit (ROU).

### ADMIN permissions:
- view my details
- edit my details
- view any user details 
- edit any user details
- add a new user to any org unit
- remove user from any org unit
- move user between any org units
- add user to any group
- remove user from any group
- move user between any groups
- create any group
- delete any group
- move group between any groups
- create org unit
- delete org unit
- move org unit between org units
- create a custom permission (user defined permission, custom permission is not considered a system permisson)
- create custom role (any role that is not a system role and is defined by a user, and comprises a collection between system and custom permissions)
- add permission to role
- add system permission to role
- assign custom role to user
- assign custom role to group
- assign system role to user
- assign system role to group

### OU_OWNER permissions:
OU_OWNER roles are cascading into sub org units. A person to which this role is assigned has the role and associated permissions automatically applied to any sub org units. Unlike SUPER_ADMIN and ADMIN roles which applies to any resources - org units, groups, users, devices, things, etc., the OU_OWNER is limited within the scope of org units owned by the person having the role. In other words, an org unit owner can view and edit user details in their org unit (or sub org units) but cannot view or edit user details in org unit they are not owner, cannot view or edit user details in org unit they have not been assigned to the appropriate role.
- view my details
- edit my details
- view user details in own org unit or their sub org unit(s)
- edit user details in own org unit or their sub org unit(s)
- add a new user to own org unit or their sub org unit(s)
- remove user from own org unit or their sub org unit(s)
- move user between own org units
- create sub org unit
- delete sub org unit from own org unit or their sub org unit(s)
- move org unit between own org units or their sub org unit(s)
- create any org unit
- delete any org unit
- move org unit between any org units
- assign OU_OWNER or OU_MANAGER role to a member of their org unit or sub org unit(s)

### OU_MANAGER
OU_MANAGER roles cascade into sub org units. A person with this role can operate in the org unit  for which the role is assigned or to operate in sub org units. Unlike SUPER_ADMIN and ADMIN roles which applies to any resources - org units, groups, users, devices, things, etc., the OU_MANAGER is limited within the scope of org unit (and the sub units) assigned to the person having the role. In other words, an org unit admin can view and edit user details in assigned org units and the sub units but cannot view or edit user details in orther org units.
- view my details
- edit my details
- view user details in assigned org unit or their sub unit(s)
- edit user details in assigned org unit or their sub unit(s)
- view user details in own org unit or their sub org unit(s)
- edit user details in own org unit or their sub org unit(s)
- add a new user to assigned org unit or their sub org unit(s)
- assign OU_MANAGER role to a member of their org unit or sub org unit(s)

### OU_MEMBER
- view my details
- edit my details
- view user details in assigned org unit or their sub unit(s)

### GROUP_OWNER
This is a group management role.

Adding a user to a group automatically assigns them GROUP_MEMBER role. A group owner can assign GROUP_OWNER or GROUP_MANAGER system role to any GROUP_MEMBER for the group they are member of. A group owner cannot assign system roles unrelated to group management.

Every group user is identified by their user id, username if the form of email, and full name. No other information such as phone number, address, etc. is revealed in group management. This being said a group owner cannot view or edit user details. This funciton is reserved to org unit roles (OU_OWNER, OU_MANAGER, OU_MEMBER roles).

- add user to own group or their sub group(s)
- remove user from own group or their sub group(s)
- move user between own groups or their sub group(s)
- create sub group in own group 
- delete sub group from own group or their sub group(s)
- move sub group between own groups or their sub group(s)
- create a custom permission (user defined permission, custom permission is not considered a system permisson)
- create custom role (any role that is not a system role and is defined by a user, and comprises a collection between system and custom permissions)
- add permission to role
- add system permission to role
- assign custom role to user
- assign custom role to group
- assign system role to user
- assign system role to group

### GROUP_MANAGER
This is a group management role.

Adding a user to a group automatically assigns them GROUP_MEMBER role. A group manager can GROUP_MANAGER system role to any GROUP_MEMBER for the group they are member of. A group manager cannot assign system roles unrelated to group management.

By group manager creating a sub group within an assigned to them group, they will become GROUP_OWNER of the sub group. The owner of the assigned group will also be considered GROUP_OWNER of the created sub group regardless if GROUP_OWNER role for the sub group has been explicitly assigned to them in DB. The owner of the assigned group is considered group owner of the sub group by the nature of business rules, not by the nature of explicitly assigned roles.

Every group user is identified by their user id, username if the form of email, and full name. No other information such as phone number, address, etc. is revealed in group management. This being said a group manager cannot view or edit user details. This funciton is reserved to org unit roles (OU_OWNER, OU_MANAGER, OU_MEMBER roles).

- add user to assigned group or their sub group(s)
- remove user from assigned group or their sub group(s)
- move user between assigned groups or their sub group(s)
- create sub group in the assigned group 
- create a custom permission (user defined permission, custom permission is not considered a system permisson)
- create custom role (any role that is not a system role and is defined by a user, and comprises a collection between system and custom permissions)
- add permission to role
- add system permission to role
- assign custom role to user
- assign custom role to group
- assign system role to user
- assign system role to group

### GROUP_MEMBER
This is an empty role to indicate the user is member of a group. There are no permissions attached to it. However, by being a member of a group, the user inherits all the roles and their permissions assigned to the group. 

# <s>PERMISSIONS</s>
AI must evaluate different permission models and recommend one of them or to improve any of them and suggest final model for the system. Ask if the recommendation is accepted, or needs a further discussion before making it final. 

Terminology: 

- __system permission :__ permission defined by the system
- __system role :__ role defined by the system. collection of system permissions only.
- __custom permission :__ permission defined by the user
- __custom role :__ role defined by the user. collection of zero or more system permissions and zero or more custom permissions.

### PERMISSION MODEL 1
- view my details
- edit my details
- view user details
- edit user details
- add user to group
- remove user from group
- move user between groups
- create group
- delete group
- move group (moves group under a different group that is not a child of the group)
- create org unit
- delete org unit
- move org unit (moves org unit under a different org unit that is not a child of the group)
- create a custom permission (user defined permission, custom permission is not considered a system permisson)
- create custom role (any role that is not a system role and is defined by a user, and comprises a collection between system and custom permissions)
- add permission to role
- add system permission to role
- assign custom role to user
- assign custom role to group
- assign system role to user
- assign system role to group

### PERMISSION MODEL 2
__assigned group__ is a group to which the signed-in user has been assigned to or any direct or indirect sub (child) group of a group to which the signed-inn user has been assigned to. an user becomes a group member when they are assigned to a group. a member of a group will have the GROUP_MEMBER system role assigned.

- view my details
- edit my details
- view user details in assigned org unit or their sub unit(s)
- edit user details in assigned org unit or their sub unit(s)
- view user details in own org unit or their sub org unit(s)
- edit user details in own org unit or their sub org unit(s)
- view any user details 
- edit any user details
- add user to assigned org unit or their sub unit(s)
- add user to own org unit or their sub org unit(s)
- remove user from own org unit or their sub org unit(s)
- move user between own org units
- add user to any org unit
- remove user from any org unit
- move user between any org units
- create sub org unit
- delete sub org unit from own org unit or their sub org unit(s)
- move org unit between own org units or their sub org unit(s)
- create any org unit
- delete any org unit
- move org unit between any org units
- add user to assigned group or their sub group(s)
- remove user from assigned group or their sub group(s)
- move user between assigned groups or their sub group(s)
- add user to own group or their sub group(s)
- remove user from own group or their sub group(s)
- move user between own groups or their sub group(s)
- add user to any group
- remove user from any group
- move user between any groups
- create sub group in the assigned group 
- create sub group in own group 
- delete sub group from own group or their sub group(s)
- move sub group between own groups or their sub group(s)
- create any group
- delete any group
- move group between any groups or their sub group(s)
- create a custom permission (user defined permission, custom permission is not considered a system permisson)
- create custom role (any role that is not a system role and is defined by a user, and comprises a collection between system and custom permissions)
- add permission to role
- add system permission to role
- assign custom role to user
- assign custom role to group
- assign system role to user
- assign system role to group

### PERMISSION MODEL 3
__given__ would mean that  the role is mapped to specific group, i.e. the role does not apply to all or any groups. 

- view my details
- edit my details
- view user details
- edit user details
- add user to given group
- remove user from given group
- move user between given groups
- create sub group in given group
- delete sub group from given group
- move sub group between given groups
- add user to any group
- remove user from any group
- move user between any groups
- create any group
- delete any group
- move group between any groups
- create org unit
- delete org unit
- move org unit between org units
- create a custom permission (user defined permission, custom permission is not considered a system permisson)
- create custom role (any role that is not a system role and is defined by a user, and comprises a collection between system and custom permissions)
- add permission to role
- add system permission to role
- assign custom role to user
- assign custom role to group
- assign system role to user
- assign system role to group

# <s>SYSTEM REQUIREMENTS</s>
- it will be written in type script, 
- locally run as node js applications with react as a front end, also locally run deployed using docker compose or kubernetes, 
- finally deployed on cloud and run in kubernetes. 
- the system should adhere to best architecture, design and coding practices, be secured, scalable, transactional, optimized in any possible way.  
- the system will start as monolithic service but over time will be split in separate micro-services e.g. organization (handling organization and organization units), group (handling group memberships), user (handling user informations), roles (handling roles and permissions assigned to users or groups)