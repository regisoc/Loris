<?php
/**
 * This file contains the Role class.
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
 * The Loris Role class
 *
 * @category Main
 * @package  Loris
 * @author   Loris Team <loris.mni@bic.mni.mcgill.ca>
 * @license  http://www.gnu.org/licenses/gpl-3.0.txt GPLv3
 * @link     https://www.github.com/aces/Loris/
 */
class Role extends RolePermissions implements
    \LORIS\StudyEntities\AccessibleResource
{
    /**
     * Stores role information
     *
     * @var array
     */
    protected $roleInfo = [];

    /**
     * Constructor
     *
     * Selects a role and its permissions
     *
     * @param ?string $roleCode Identifies the role
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
            "SELECT * FROM role WHERE Code = :co",
            ['co' => $roleCode]
        );

        // if null, consider it as the "blocked" role.
        if (is_null($row)) {
            $row = self::_getBlockedRole();
        }

        // New role obj
        $obj = new Role;

        // attribute DB info
        $obj->roleInfo = $row;

        //
        return $obj;
    }

    /**
     * Get the blocked role archetype from DB.
     *
     * @return ?array
     * @access private
     * @static
     */
    private static function _getBlockedRole(): ?array
    {
        return \NDB_Factory::singleton()->database()->pselectRow(
            "SELECT * FROM role WHERE Code = 'blocked'",
            []
        );
    }

    /**
     * Inserts data into the `role` table.
     *
     * @param array $set The array formatted for use in a Database call
     *
     * @return void
     * @access public
     * @static
     */
    public static function insert(array $set): void
    {
        \NDB_Factory::singleton()->database()->insert('role', $set);
    }


    /**
     * Updates a role
     *
     * @param array $set The array formatted for use in a Database call
     *
     * @return void
     * @access public
     */
    public function update(array $set): void
    {
        \NDB_Factory::singleton()->database()->update(
            'role',
            $set,
            ['RoleID' => $this->roleInfo['RoleID']]
        );
    }


    /**
     * Returns the reole information as array.
     * 
     * @return array
     */
    public function asArray() : array
    {
        return $this->roleInfo;
    }

    /**
     * Returns data from the roleInfo array according to the key provided
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
        return ($var === '') ? $this->roleInfo : $this->roleInfo[$var];
    }

    /**
     * Get the role's id
     *
     * @return int
     */
    function getId(): int
    {
        return intval($this->roleInfo['RoleID']);
    }

    /**
     * Get role code
     *
     * @return string
     */
    function getCode(): string
    {
        return $this->roleInfo['Code'];
    }

    /**
     * Get the role's description
     *
     * @return string
     */
    function getDescription(): string
    {
        return $this->roleInfo['Description'];
    }

    /**
     * Implements the AccessibleResource interface. Return true if the role is
     * accessible by the user.
     *
     * @param \User $user The user whose access should be
     *                    validated
     *
     * @return bool
     */
    public function isAccessibleBy(\User $user): bool
    {
        return $user->hasPermission('role_view')
                || $user->hasPermission('role_edit')
                || $user->hasPermission('role_assign');
    }

    /**
     * Checks if the string is a role within the database
     *
     * @param string $roleCode the role code to be checked
     *
     * @return boolean
     */
    public static function exists($roleCode)
    {
        $roleFound = \NDB_Factory::singleton()->database()->pselectOne(
            "SELECT RoleID FROM role WHERE Code = :rcode",
            ['rcode' => $roleCode]
        );
        return !is_null($roleFound);
    }

    /**
     * Useful during new Role creation or for code comparison.
     * Generate the corresponding role code from a given role name. 
     * 
     * @param string $name a role name
     * 
     * @return string a code version of the name
     */
    public static function generateCodeFromName(string $name)
    {
        $code = strtolower(trim($name));
        $code = str_replace("  ", " ", $code);
        $code = str_replace(" ", "_", $code);
        return $code;
    }
}