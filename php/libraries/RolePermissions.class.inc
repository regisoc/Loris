<?php declare(strict_types=1);
/**
 * The RolePermissions class manages checking of role permissions
 *
 * PHP Version 7
 *
 * @category Main
 * @package  Main
 * @author   Loris Team <loris.mni@bic.mni.mcgill.ca>
 * @license  http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 * @link     https://www.github.com/aces/Loris/
 */

/**
 * Manages role permissions
 *
 * @category Main
 * @package  Main
 * @author   Loris Team <loris.mni@bic.mni.mcgill.ca>
 * @license  http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 * @link     https://www.github.com/aces/Loris/
 */
class RolePermissions
{
    /**
     * Role's ID
     *
     * @var ?string
     */
    var $roleID;

    /**
     * Stores the permissions
     *
     * @var array<string,bool>
     */
    private $permissions = [];

    /**
     * Constructor
     *
     * Fills the permissions property based on role code
     *
     * @param string|null $roleCode Identifies the role
     *
     * @return bool true if the role exists, false otherwise
     */
    function select(?string $roleCode): bool
    {
        $db = \NDB_Factory::singleton()->database();
        
        // get the role ID from the database
        $roleID = $db->pselectOne(
            "SELECT RoleID FROM roles WHERE RoleID =:rid",
            ['rid' => $roleCode]
        );
        if ($roleID === null) {
            return false;
        }
        $this->roleID = $roleID;

        // load the role's permissions
        $this->setPermissions();

        return true;
    }


    /**
     * Loads the role's permissions
     *
     * @return void
     * @access private
     */
    function setPermissions(): void
    {
        $db = \NDB_Factory::singleton()->database();

        // get all the permissions for this user
        $results = $db->pselect(
            "SELECT p.code, rpr.RoleID
            FROM permissions p
                LEFT JOIN role_permission_rel rpr ON (p.permID = rpr.permID)
            WHERE rpr.roleID = :rid",
            ['rid' => $this->roleID]
        );

        // reset the array
        $this->permissions = [];

        // Fill the permissions array of this RolePermissions object with the
        // values extracted for this role from the database.
        if (is_array($results) and !empty($results)) {
            foreach ($results as $row) {
                $roleMatch = $row['RoleID'] === $this->roleID;
                $this->permissions[$row['code']] = $roleMatch;
            }
        }
    }


    /**
     * Determines if the role has the permission to access a specific module
     * or page.
     *
     * @param string $code The permission code
     *
     * @return bool If the role has a permission.
     */
    public function hasPermission(string $code): bool
    {
        return $this->_permissionTrueAndValid('superuser')
            || $this->_permissionTrueAndValid($code);
    }

    /**
     * Check if a given permission code is present in a role's list of
     * permissions. Also validates that the permission code is real.
     *
     * @param string $code Permission code to test.
     *
     * @return bool The setting of permission code $permission
     */
    private function _permissionTrueAndValid(string $code): bool
    {
        if (!isset($this->permissions[$code])) {
            throw new ConfigurationException("Invalid permission code '$code'");
        }
        return intval($this->permissions[$code]) === 1;
    }

    /**
     * Used to test whether a role has ALL of an array of specified permissions.
     * Returns false on the first permission that the role doesn't have.
     *
     * @param string[] $permissions Array of permissions codes.
     *
     * @return bool Whether the role has all the permissions in $permissions.
     */
    public function hasAllPermissions(array $permissions): bool
    {
        if (count($permissions) === 0) {
            throw new LorisException(
                "Cannot call hasAllPermissions with an empty array!"
            );
        }
        foreach ($permissions as $p) {
            if (!$this->_permissionTrueAndValid($p)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Used to test whether a role has ANY of an array of specified permissions.
     *
     * @param string[] $permissions Array of permissions codes.
     *
     * @return bool Whether the role has any of the permissions in $permissions.
     */
    public function hasAnyPermission(array $permissions): bool
    {
        if (count($permissions) === 0) {
            throw new LorisException(
                "Cannot call hasAnyPermission with an empty array!"
            );
        }
        foreach ($permissions as $p) {
            if ($this->hasPermission($p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the permissions array
     *
     * @return array
     * @access public
     */
    function getPermissions(): array
    {
        return $this->permissions;
    }


    /**
     * Add permissions to a role
     *
     * @param array $set Array of permission IDs to add
     *
     * @return void
     * @note   If saving permissions, remove all permissions first
     */
    function addPermissions(array $set): void
    {
        $db = \NDB_Factory::singleton()->database();

        // add the permissions
        foreach ($set as $value) {
            $db->insert(
                'role_permission_rel',
                [
                    'RoleID' => $this->roleID,
                    'permID' => $value,
                ]
            );
        }

        // refresh the role permissions
        $this->setPermissions();
    }


    /**
     * Removes permissions from a role
     *
     * @param array|null $set Array of permission IDs to remove
     *
     * @return void
     * @note   Passing no arguments deletes all permissions
     */
    function removePermissions(?array $set = null): void
    {
        $db = \NDB_Factory::singleton()->database();

        // remove all permissions
        if (is_null($set)) {
            $db->delete(
                'role_permission_rel',
                ['RoleID' => $this->roleID]
            );
        } else {
            // remove the permissions
            foreach ($set as $value) {
                $db->delete(
                    'role_permission_rel',
                    [
                        'RoleID' => $this->roleID,
                        'permID' => $value,
                    ]
                );
            }
        }

        // refresh the user permissions
        $this->setPermissions();
    }


    /**
     * Returns an array of the role's permission IDs
     *
     * @return array
     * @access public
     */
    function getPermissionIDs(): array
    {
        $db = \NDB_Factory::singleton()->database();

        // get all the permissions for this user
        $results = $db->pselect(
            "SELECT DISTINCT rpr.permID
            FROM role_permission_rel rpr
            WHERE RoleID = :rid",
            ['rid' => $this->roleID]
        );

        // isolate and return numeric permission values
        $permIDs = [];
        foreach ($results as $row) {
            foreach ($row as $v) {
                $permIDs[] = $v;
            }
        }
        return $permIDs;
    }


    /**
     * Returns an array with all permissions information for the role
     *
     * @param \LORIS\LorisInstance $loris The LORIS instance to get
     *                                    permissions from.
     *
     * @return array
     */
    function getPermissionsVerbose(\LORIS\LorisInstance $loris): array
    {
        $db = $loris->getDatabaseConnection();

        // get verbose 
        $query = "SELECT
                p.permID,
                p.code,
                p.description,
                p.moduleID,
                GROUP_CONCAT(pt.Description) as action
            FROM permissions p 
                JOIN role_permission_rel rpr ON (p.permID=rpr.permID)
                LEFT JOIN modules m ON (p.moduleID=m.ID)
                LEFT JOIN permission_permission_type_rel pptr ON (pptr.permID = p.permID)
                LEFT JOIN permission_type pt ON (pt.PermissionTypeID = pptr.PermissionTypeID)
            WHERE rpr.RoleID = :rid and m.Active='Y'
            GROUP BY p.permID, p.code, p.description, p.moduleID
            ORDER BY m.Name, p.description";
        $results = $db->pselect($query, []);
        
        // Build new meaningful description from combination of columns
        // Module Long Name: action description
        $modules = \Module::getActiveModulesIndexed($loris);
        foreach ($results as $key=>$perm) {
            $newDesc = '';
            if (!empty($perm['moduleID'])) {
                $newDesc = $modules[$perm['moduleID']]->getLongName() . ": ";
            }
            $newDesc .= empty($perm['action']) ? "" : $perm['action'] . " ";
            $newDesc .= $perm['description'];

            $results[$key]['label'] = $newDesc;
        }
        return $results;
    }
}

