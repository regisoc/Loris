<?php
/**
 * This file contains the Permission class.
 *
 * PHP Version 5-7
 *
 * @category Main
 * @package  Loris
 * @author   Loris Team <loris.mni@bic.mni.mcgill.ca>
 * @license  http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 * @link     https://www.github.com/aces/Loris/
 */

/**
 * The Loris Permission class
 *
 * @category Main
 * @package  Loris
 * @author   Loris Team <loris.mni@bic.mni.mcgill.ca>
 * @license  http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 * @link     https://www.github.com/aces/Loris/
 */
class Permission
{
    // /**
    //  * Stores Database being used
    //  *
    //  * @var    $DB Database
    //  * @access private
    //  */
    // var $DB;

    // /**
    //  * Permission constructor.
    //  *
    //  * @param Database $Database database
    //  */
    // function __construct($Database)
    // {
    //     $this->DB = $Database;
    // }

    /**
     * Stores user information
     *
     * @var array
     */
    protected $permissionInfo = [];

    /**
     * Constructor
     *
     * Selects a permission
     *
     * @param ?string $permissionCode Identifies the role
     *
     * @return \Role A Role object if the Role specified by $roleCode exists
     * @access public
     */
    public static function &factory(?string $roleCode = null): \Role
    {
        // create DB object
        $DB = \NDB_Factory::singleton()->database();

        // get user data from database
        $row = $DB->pselectRow(
            "SELECT * FROM roles WHERE Code = :co",
            ['co' => $roleCode]
        );

        // if null, consider it as the "blocked" role.
        if (is_null($row)) {
            return self::_getBlockedRole();
        }

        // New role obj
        $obj = new Role;

        // attribute DB info
        $obj->roleInfo = $row;

        //
        return $obj;
    }

    /**
     * Singleton method. Retrieve the permission passed as parameter, but only
     * 1 instance.
     *
     * @param ?string $permissionCode Identifies the permission
     *
     * @return Permission
     * @access public
     * @static
     */
    public static function &singleton(?string $permissionCode = null): \Permission
    {
        static $instance;
        if (is_null($instance)) {
            $instance = Permission::factory($permissionCode);
        }
        return $instance;
    }

    /**
     * Inserts data into the `permissions` table.
     *
     * @param array $set The array formatted for use in a Database call
     *
     * @return void
     * @access public
     * @static
     */
    public static function insert(array $set): void
    {
        \NDB_Factory::singleton()->database()->insert('permissions', $set);
    }


    /**
     * Updates a permission
     *
     * @param array $set The array formatted for use in a Database call
     *
     * @return void
     * @access public
     */
    public function update(array $set): void
    {
        \NDB_Factory::singleton()->database()->update(
            'permissions',
            $set,
            ['permID' => $this->permissionInfo['permID']]
        );
    }

    /**
     * Returns data from the permissionInfo array according to the key provided
     * as argument.
     *
     * @param string $var Name of variable to get
     *
     * @note   Call without any arguments to get the entire user data array
     * @return array<array|string>|string
     * @access public
     * @throws LorisException
     */
    public function getData(string $var = '')
    {
        return ($var === '') ? $this->permissionInfo : $this->permissionInfo[$var];
    }

    /**
     * Get the permission's id
     *
     * @return int
     */
    function getId(): int
    {
        return intval($this->permissionInfo['permID']);
    }

    /**
     * Get permission code (permission name)
     *
     * @return string
     */
    function getCode(): string
    {
        return $this->permissionInfo['code'];
    }

    /**
     * Get the permission's description
     *
     * @return string
     */
    function getDescription(): string
    {
        return $this->permissionInfo['description'];
    }

    /**
     * Get the permission's moduleID
     *
     * @return ?int
     */
    function getModuleID(): ?int
    {
        return intval($this->permissionInfo['moduleID']);
    }

    /**
     * Get the permission's action
     *
     * @return string
     */
    function getAction(): string
    {
        return $this->permissionInfo['action'];
    }






    // ----------------- TO UTILS ??


    /**
     * Gets the list of permissions in the database.
     *
     * @return array Associative array in the form $permissionID=>$permissionName
     */
    function getPermissions()
    {
        $permissions = $this->DB->pselectColWithIndexKey(
            "SELECT permID, code FROM permissions",
            [],
            "permID"
        );
        return $permissions;
    }

    /**
     * Gets the list of permission labels in the database.
     *
     * @return array Associative array in the form $permissionID=>$permissionLabel
     */
    function getPermissionLabels()
    {
        $permissions = $this->DB->pselectColWithIndexKey(
            "SELECT permID, description FROM permissions",
            [],
            "permID"
        );
        return $permissions;
    }

    /**
     * Checks if the string is a permission within the database
     *
     * @param string $permissionName the permission to be checked
     *
     * @return boolean
     */
    function isPermission($permissionName)
    {
        $permissions = $this->getPermissions();
        return in_array($permissionName, $permissions, true);
    }

    /**
     * Gets the ID of a permission given its name
     *
     * @param string $permissionName the permission name for which the ID is needed
     *
     * @throws LorisException if permission does not exist
     *
     * @return ?int
     */
    function getPermissionIDFromName($permissionName)
    {
        if (!$this->isPermission($permissionName)) {
            throw new LorisException(
                "Could not retrieve the permission ID for 
                permission '$permissionName'"
            );
        }

        $permissionID = intval($this->DB->pselectOne(
            "SELECT permID
            FROM permissions
            WHERE code=:PN",
            ["PN" => $permissionName]
        ));
        return ($permissionID !== 0) ? $permissionID : null;
    }

    /**
     * Gets the NAME of a permission given its ID
     *
     * @param int $permissionID the permission ID for which the name is needed
     *
     * @throws LorisException if permission ID does not exist
     *
     * @return string
     */
    function getPermissionNameFromID($permissionID)
    {
        $permissionName = $this->DB->pselectOne(
            "SELECT code
            FROM permissions
            WHERE permID=:PID",
            ["PID" => $permissionID]
        );

        if (empty($permissionName)) {
            throw new LorisException(
                "Could not retrieve the permission name for 
                permission ID '$permissionID'"
            );
        }
        return $permissionName;
    }

    /**
     * Gets the complete description for a permission.
     *
     * @param int $permID permission ID.
     *
     * @return ?string the description.
     */
    function getDescriptionUsingPermID($permID): ?string
    {
        return $this->DB->pselectOne(
            "SELECT Description FROM permissions WHERE permID =:pID",
            ['pID' => $permID]
        );
    }

    // /**
    //  * Gets the roles associated to a permission
    //  *
    //  * @param int $permissionID the permission
    //  *
    //  * @return array non-associative with values being the permission IDs
    //  */
    // function getPermissionRoleIDs($permissionID)
    // {
    //     $roles = $this->DB->pselectCol(
    //         "SELECT RoleID
    //         FROM role_permission_rel
    //         WHERE PermissionID=:PID",
    //         ["PID" => $permissionID]
    //     );
    //     return $roles;
    // }


    // SHOULD BE IN UserPermission class.
    // /**
    //  * Returns all the users with the permission
    //  *
    //  * @param int $permissionID the permission
    //  *
    //  * @return array Associative array ($userID=>$RealName) that have the permission
    //  */
    // function getPermissionUsers($permissionID)
    // {
    //     $usersWithPermission = $this->DB->pselectColWithIndexKey(
    //         "SELECT upr.userID, u.Real_name
    //         FROM user_perm_rel upr 
    //             JOIN users u ON u.ID=upr.userID
    //             WHERE upr.permId=:PID",
    //         ["PID" => $permissionID],
    //         "userID"
    //     );
    //     return $usersWithPermission;
    // }

    // /**
    //  * Gets all the users' permissions based on their roles
    //  *
    //  * @param array $roleIDs role set associated with a user
    //  *
    //  * @return array associative array ($permissionID=>$permissionName) of
    //  *               permissions associated with the given permission set
    //  */
    // function getPermissionsFromRoles($roleIDs)
    // {
    //     $roleObject  = new \Role($this->DB);
    //     $permissions = $this->getPermissions();

    //     $userPermissions = array();

    //     foreach ($roleIDs as $roleID) {
    //         $rolePermissions = $roleObject->getRolePermissionIDs($roleID);
    //         foreach ($rolePermissions as $permissionID) {
    //             //if permissions overlap between roles, this will
    //             //just overwrite data with the same data
    //             $userPermissions[$permissionID] = $permissions[$permissionID];
    //         }
    //     }

    //     return $userPermissions;
    // }


}