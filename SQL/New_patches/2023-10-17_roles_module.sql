
-- alter permissions
-- the roles category is moved to the roles table.

-- update bvl_feedback and data_entry to permission.
UPDATE `permissions`
  SET categoryID = '1'
  WHERE 'code' IN ('superuser', 'bvl_feedback', 'data_entry');

-- delete permission_category because roles are a new table.
SET foreign_key_checks = 0;
DELETE FROM `permissions_category`;
DROP TABLE `permissions_category`;
ALTER TABLE `permissions` DROP FOREIGN KEY `fk_permissions_1`;
ALTER TABLE `permissions` DROP COLUMN categoryID;
SET foreign_key_checks = 1;

-- add role table
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
  `RoleID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `Code` varchar(255) NOT NULL DEFAULT '',
  `Name` varchar(255) NOT NULL DEFAULT '',
  `Description` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`RoleID`),
  UNIQUE KEY `Code` (`Code`)
) ENGINE=InnoDB DEFAULT CHARSET='utf8';


INSERT INTO `role` VALUES
  (1,'blocked', 'Blocked', 'A blocked user: user has access to nothing.'),
  (2,'administrator', 'Administrator', 'An administrator: has access to everything, no restrictions.');

-- add to modules
INSERT INTO modules (Name, Active) VALUES ('roles', 'Y');

-- add new permissions (related to roles module)
INSERT INTO `permissions` (`code`, `description`, `moduleID`) 
VALUES
  ('roles_view','Role',(SELECT ID FROM modules WHERE Name='roles')),
  ('roles_assign','Role',(SELECT ID FROM modules WHERE Name='roles')),
  ('roles_edit','Role',(SELECT ID FROM modules WHERE Name='roles'));

INSERT INTO `permission_permission_type_rel` (permID, PermissionTypeID)
VALUES 
  -- role_view = view
  (
    (SELECT permID FROM permissions WHERE code = 'roles_view'),
    (SELECT PermissionTypeID FROM permission_type WHERE Description = 'View')
  ),
  -- role_assign = Edit
  (
    (SELECT permID FROM permissions WHERE code = 'roles_assign'),
    (SELECT PermissionTypeID FROM permission_type WHERE Description = 'Edit')
  ),
  -- role_edit = create, edit, delete
  (
    (SELECT permID FROM permissions WHERE code = 'roles_edit'),
    (SELECT PermissionTypeID FROM permission_type WHERE Description = 'Create')
  ),
  (
    (SELECT permID FROM permissions WHERE code = 'roles_edit'),
    (SELECT PermissionTypeID FROM permission_type WHERE Description = 'Edit')
  ),
  (
    (SELECT permID FROM permissions WHERE code = 'roles_edit'),
    (SELECT PermissionTypeID FROM permission_type WHERE Description = 'Delete')
  );

-- add role_permission_rel table
DROP TABLE IF EXISTS `role_permission_rel`;
CREATE TABLE `role_permission_rel` (
  `RoleID` int(10) unsigned NOT NULL default '0',
  `permID` int(10) unsigned NOT NULL default '0',
  PRIMARY KEY  (`PermissionTypeID`,`permID`),
  KEY `FK_permission_permission_type_rel_2` (`permID`),
  CONSTRAINT `FK_permission_permission_type_rel_2`
  FOREIGN KEY (`permID`)
    REFERENCES `permissions` (`permID`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `FK_permission_permission_type_rel_1`
  FOREIGN KEY (`PermissionTypeID`)
    REFERENCES `permission_type` (`PermissionTypeID`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET='utf8';

-- -- add to admin account
-- INSERT IGNORE INTO `user_perm_rel` (userID, permID)
--     SELECT u.ID, p.permID
--     FROM users u JOIN permissions p
--     WHERE u.userid = 'admin'
--     ORDER BY p.permID;
