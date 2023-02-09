SET FOREIGN_KEY_CHECKS=0;
TRUNCATE TABLE `physiological_coord_system_type`;
LOCK TABLES `physiological_coord_system_type` WRITE;
INSERT INTO `physiological_coord_system_type` (`PhysiologicalCoordSystemTypeID`, `Name`) VALUES (3,'AnatomicalLandmark');
INSERT INTO `physiological_coord_system_type` (`PhysiologicalCoordSystemTypeID`, `Name`) VALUES (5,'DigitizedHeadPoints');
INSERT INTO `physiological_coord_system_type` (`PhysiologicalCoordSystemTypeID`, `Name`) VALUES (2,'Fiducials');
INSERT INTO `physiological_coord_system_type` (`PhysiologicalCoordSystemTypeID`, `Name`) VALUES (4,'HeadCoil');
INSERT INTO `physiological_coord_system_type` (`PhysiologicalCoordSystemTypeID`, `Name`) VALUES (1,'Not registered');
UNLOCK TABLES;
SET FOREIGN_KEY_CHECKS=1;
