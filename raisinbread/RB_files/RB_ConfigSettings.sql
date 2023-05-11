SET FOREIGN_KEY_CHECKS=0;
TRUNCATE TABLE `ConfigSettings`;
LOCK TABLES `ConfigSettings` WRITE;
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (1,'study','Settings related to details of the study',1,0,NULL,NULL,'Study',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (2,'additional_user_info','Display additional user profile fields on the User accounts page (e.g. Institution, Position, Country, Address)',1,0,'boolean',1,'Additional user information',15);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (3,'title','Full descriptive title of the study',1,0,'text',1,'Study title',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (4,'studylogo','Filename containing logo of the study. File should be located under the htdocs/images/ folder',1,0,'text',1,'Study logo',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (5,'useEDC','Use EDC (Expected Date of Confinement) for birthdate estimations if the study involves neonatals',1,0,'boolean',1,'Use EDC',12);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (6,'ageMin','Minimum candidate age in years (0+)',1,0,'text',1,'Minimum candidate age',7);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (7,'ageMax','Maximum candidate age in years',1,0,'text',1,'Maximum candidate age',8);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (9,'useFamilyID','Enable if family members are recruited for the study',1,0,'boolean',1,'Use family',11);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (10,'startYear','Start year for study recruitment or data collection',1,0,'text',1,'Start year',5);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (11,'endYear','End year for study recruitment or data collection',1,0,'text',1,'End year',6);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (12,'dobFormat','Format of the Date of Birth',1,0,'date_format',1,'DOB Format',9);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (13,'useExternalID','Enable if data is used for blind data distribution, or from external data sources',1,0,'boolean',1,'Use external ID',12);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (14,'useProband','Enable for proband data collection',1,0,'boolean',1,'Use proband',11);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (16,'useScreening','Enable if there is a Screening stage with its own distinct instruments, administered before the Visit stage',1,0,'boolean',1,'Use screening',14);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (17,'excluded_instruments','Instruments to be excluded from the Data Dictionary and download via the Data Query Tool',1,1,'instrument',1,'Excluded instruments',16);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (18,'DoubleDataEntryInstruments','Instruments for which double data entry should be enabled',1,1,'instrument',1,'Double data entry instruments',17);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (19,'InstrumentResetting','Allows resetting of instrument data',1,0,'boolean',1,'Instrument Resetting',18);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (20,'SupplementalSessionStatus','Display supplemental session status information on Timepoint List page',1,0,'boolean',1,'Use Supplemental Session Status',19);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (21,'useScanDone','Used for identifying timepoints that have (or should have) imaging data',1,0,'boolean',1,'Use Scan Done',20);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (22,'allowPrenatalTimepoints','Determines whether creation of timepoints prior to Date of Birth is allowed',1,0,'boolean',1,'Allow Prenatal Timepoints',21);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (23,'ImagingUploaderAutoLaunch','Allows running the ImagingUpload pre-processing scripts',1,0,'boolean',1,'ImagingUploader Auto Launch',22);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (24,'citation_policy','Citation Policy for Acknowledgements module',1,0,'textarea',1,'Citation Policy',23);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (25,'CSPAdditionalHeaders','Extensions to the Content-security policy allow only for self-hosted content',1,0,'text',1,'Content-Security Extensions',24);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (26,'paths','Specify directories where LORIS-related files are stored or created. Take care when editing these fields as changing them incorrectly can cause certain modules to lose functionality.',1,0,NULL,NULL,'Paths',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (27,'imagePath','Path to images for display in Imaging Browser (e.g. /data/$project/data/) ',1,0,'web_path',26,'Images',9);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (28,'base','The base filesystem path where LORIS is installed',1,0,'web_path',26,'Base',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (33,'log','Path to logs (relative path starting from /var/www/$projectname)',1,0,'path',26,'Logs',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (34,'IncomingPath','Path for imaging data transferred to the project server (e.g. /data/incoming/$project/)',1,0,'web_path',26,'Incoming data',7);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (35,'MRICodePath','Path to directory where Loris-MRI (git) code is installed',1,0,'path',26,'LORIS-MRI code',6);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (36,'MRIUploadIncomingPath','Path to the upload directory for incoming MRI studies',1,0,'web_path',26,'MRI Incoming Directory',7);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (37,'GenomicDataPath','Path to Genomic data files',1,0,'web_path',26,'Genomic Data Path',8);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (38,'mediaPath','Path to uploaded media files',1,0,'web_path',26,'Media',9);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (39,'gui','Settings related to the overall display of LORIS',1,0,NULL,NULL,'GUI',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (42,'StudyDescription','Description of the Study',1,0,'textarea',39,'Study Description',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (43,'www','Web address settings',1,0,NULL,NULL,'WWW',4);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (44,'host','Host',1,0,'text',43,'Host',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (46,'mantis_url','Bug tracker URL',0,0,'text',43,'Bug tracker URL',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (47,'dashboard','Settings that affect the appearance of the dashboard and its charts',1,0,NULL,NULL,'Dashboard',5);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (48,'projectDescription','Description of the study displayed in main dashboard panel',1,0,'textarea',47,'Project Description',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (49,'recruitmentTarget','Target number of participants for the study',1,0,'text',47,'Target number of participants',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (50,'imaging_modules','DICOM Archive and Imaging Browser settings',1,0,NULL,NULL,'Imaging Modules',6);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (51,'patientIDRegex','Regex for masking the Patient ID header field',1,0,'text',50,'Patient ID regex',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (52,'patientNameRegex','Regex for masking the Patient Name header field',1,0,'text',50,'Patient name regex',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (53,'LegoPhantomRegex','Regex for identifying a Lego Phantom scan header',1,0,'text',50,'Lego phantom regex',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (54,'LivingPhantomRegex','Regex to be used on Living Phantom scan header',1,0,'text',50,'Living phantom regex',4);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (55,'showTransferStatus','Show transfer status in the DICOM Archive table',1,0,'boolean',50,'Show transfer status',5);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (56,'tblScanTypes','Scan types from the mri_scan_type table that the project wants to see displayed in Imaging Browser table',1,1,'scan_type',50,'Imaging Browser Tabulated Scan Types',6);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (57,'statistics','Statistics module settings',1,0,NULL,NULL,'Statistics',7);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (58,'excludedMeasures','Instruments to be excluded from Statistics calculations',1,1,'instrument',57,'Excluded instruments',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (59,'mail','LORIS email settings for notifications sent to users',1,0,NULL,NULL,'Email',8);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (60,'From','Sender email address header (e.g. admin@myproject.loris.ca)',1,0,'email',59,'From',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (61,'Reply-to','Reply-to email address header (e.g. admin@myproject.loris.ca)',1,0,'email',59,'Reply-to',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (62,'X-MimeOLE','X-MimeOLE',1,0,'text',59,'X-MimeOLE',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (63,'uploads','Settings related to file uploading',1,0,NULL,NULL,'Uploads',9);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (64,'FileGroup','Determines the group permission for new subdirectories created for uploaded files',1,0,'text',63,'File Group for Uploads',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (65,'APIKeys','Specify any API keys required for LORIS',1,0,NULL,NULL,'API Keys',10);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (66,'JWTKey','Secret key for signing JWT tokens on this server. This should be unique and never shared with anyone. ',1,0,'text',65,'JWT Secret Key',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (67,'reCAPTCHAPrivate','Private Key for Google reCAPTCHA',1,0,'text',65,'reCAPTCHA Private Key',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (68,'reCAPTCHAPublic','Public Key for Google reCaptcha',1,0,'text',65,'reCAPTCHA Public Key',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (69,'imaging_pipeline','Imaging Pipeline settings',1,0,NULL,NULL,'Imaging Pipeline',12);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (70,'dataDirBasepath','Base Path to the data directory of Loris-MRI',1,0,'web_path',69,'Loris-MRI Data Directory',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (71,'prefix','Study prefix or study name',1,0,'text',69,'Study Name',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (72,'mail_user','User to be notified during imaging pipeline execution',1,0,'text',69,'User to notify when executing the pipeline',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (73,'get_dicom_info','Full path to get_dicom_info.pl',1,0,'path',69,'Full path to get_dicom_info.pl script',4);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (74,'horizontalPics','Enable generation of horizontal pictures',1,0,'boolean',69,'Horizontal pictures creation',5);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (75,'create_nii','Enable creation of NIfTI files',1,0,'boolean',69,'NIfTI file creation',6);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (76,'converter','If converter is set to dcm2mnc, the c-version of dcm2mnc will be used. If however you want to use any of the various versions of the converter, you will have to specify what it is called and the uploader will try to invoke it',1,0,'text',69,'DICOM converter tool to use (dcm2mnc or dcm2niix)',7);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (77,'tarchiveLibraryDir','Location of storing the library of used tarchives. If this is not set, they will not be moved',1,0,'path',69,'Path to Tarchives',8);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (78,'lookupCenterNameUsing','DICOM field (either PatientName or PatientID) to use to get the patient identifiers and the center name of the DICOM study',1,0,'lookup_center',69,'Patient identifiers and center name lookup variable',9);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (79,'createCandidates','Enable candidate creation in the imaging pipeline',1,0,'boolean',69,'Enable candidate creation',10);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (80,'is_qsub','Enable use of batch management in the imaging pipeline',1,0,'boolean',69,'Project batch management used',15);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (82,'DTI_volumes','Number of volumes in native DTI acquisitions',1,0,'text',69,'Number of volumes in native DTI acquisitions',16);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (83,'t1_scan_type','Scan type of native T1 acquisition (as in the mri_scan_type table)',1,0,'text',69,'Scan type of native T1 acquisition',17);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (84,'reject_thresh','Max number of directions that can be rejected to PASS QC',1,0,'text',69,'Max number of DTI rejected directions for passing QC',18);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (85,'niak_path','Path to niak quarantine to use if mincdiffusion will be run (option -runMincdiffusion set when calling DTIPrep_pipeline.pl)',1,0,'path',69,'NIAK Path',19);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (86,'QCed2_step','DTIPrep protocol step at which a secondary QCed dataset is produced (for example one without motion correction and eddy current correction would be saved at INTERLACE_outputDWIFileNameSuffix step of DTIPrep)',1,0,'text',69,'Secondary QCed dataset',20);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (87,'issue_tracker_url','URL of the preferred issue tracker for this study',1,0,'text',43,'Issue Tracker URL',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (88,'excluded_series_description','Series description to be excluded from insertion into the database (typically localizers and scouts)',1,1,'text',69,'Series description to exclude from imaging insertion',21);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (89,'useConsent','Enable if the study uses the loris architecture for consent',1,0,'boolean',1,'Use consent',15);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (90,'ComputeDeepQC','Determines whether a call is made from LORIS-MRI to the DeepQC app for automatic QC prediction',1,0,'boolean',69,'Compute automatic QC',22);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (91,'ImagingBrowserLinkedInstruments','Instruments that the users want to see linked from Imaging Browser',1,1,'instrument',50,'Imaging Browser Links to Instruments',7);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (92,'MriConfigFile','Name of the Perl MRI config file (stored in dicom-archive/.loris_mri/)',1,0,'text',69,'Name of the Perl MRI config file',23);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (93,'default_bids_vl','Default visit label to use when no visit label set in the BIDS dataset',1,0,'text',69,'Default visit label for BIDS dataset',14);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (94,'reference_scan_type_for_defacing','Scan type to use as a reference for registration when defacing anatomical images (typically a T1W image)',1,0,'scan_type',69,'Scan type to use as a reference for defacing (typically a T1W image)',26);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (95,'modalities_to_deface','Modalities for which defacing should be run and defaced image inserted in the database',1,1,'scan_type',69,'Modalities on which to run the defacing pipeline',27);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (96,'compute_snr_modalities','Modalities for which the SNR should be computed when running the insertion MRI scripts',1,1,'scan_type',69,'Modalities on which SNR should be calculated',25);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (97,'publication_uploads','Path to uploaded publications',1,0,'web_path',26,'Publications',11);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (98,'publication_deletions','Path to deleted publications',1,0,'web_path',26,'Deleted Publications',11);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (99,'usePwnedPasswordsAPI','Whether to query the Have I Been Pwned password API on password changes to prevent the usage of common and breached passwords',1,0,'boolean',1,'Enable \"Pwned Password\" check',22);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (100,'EnvironmentFile','Name of the environment file that need to be sourced for the imaging pipeline',1,0,'text',69,'Name of the environment file',24);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (101,'MINCToolsPath','Path to the MINC tools',1,0,'web_path',26,'Path to the MINC tools',12);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (102,'documentRepositoryPath','Path to uploaded document repository files',1,0,'text',26,'Document Repository Upload Path',13);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (103,'dataReleasePath','Path to uploaded data release files',1,0,'text',26,'Data Release Upload Path',14);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (104,'dodFormat','Format of the Date of Death',1,0,'date_format',1,'DOD Format',10);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (105,'dateDisplayFormat','The date format to use throughout LORIS for displaying date information - formats for date inputs are browser- and locale-dependent.',1,0,'text',1,'Date display format',27);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (106,'IssueTrackerDataPath','Path to Issue Tracker data files',1,0,'web_path',26,'Issue Tracker Data Path',8);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (107,'adminContactEmail','An email address that users can write to in order to report issues or ask question',1,0,'text',1,'Administrator Email',28);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (111,'logs','Settings related to logging',1,0,NULL,NULL,'Log Settings',12);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (112,'database_log_level','Verbosity of database logging',1,0,'log_level',111,'Database Log Level',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (113,'request_log_level','Verbosity of HTTP request logs',1,0,'log_level',111,'HTTP Request Log Level',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (114,'exception_log_level','Verbosity of PHP exception logging',1,0,'log_level',111,'HTTP Request Log Level',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (115,'minc2bids','Settings related to converting MINC to BIDS LORIS-MRI tool script',1,0,NULL,NULL,'MINC to BIDS Converter Tool Options',13);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (116,'bids_dataset_authors','Authors for the BIDS dataset',1,1,'text',115,'BIDS Dataset Authors',1);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (117,'bids_acknowledgments_text','Acknowledgments to be added in the dataset_description.json file of the BIDS dataset created out of the MINC files',1,0,'text',115,'BIDS Dataset Acknowledgments',2);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (118,'bids_readme_text','Content to be added to the README of the BIDS dataset generated out of the MINC files',1,0,'textarea',115,'BIDS Dataset README',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (119,'bids_validator_options_to_ignore','Options to be ignored for BIDS validation',1,1,'text',115,'BIDS Validation options to ignore',4);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (120,'MriPythonConfigFile','Name of the Python MRI config file (stored in dicom-archive/.loris_mri/)',1,0,'text',69,'Name of the Python MRI config file',28);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (121,'aws','Settings related to AWS services',1,0,NULL,NULL,'AWS Settings',13);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (122,'AWS_S3_Endpoint','Endpoint to use for accessing files stored in S3. Endpoint or region are required for S3 support.',1,0,'text',121,'AWS S3 Endpoint',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (123,'AWS_S3_Region','AWS Region to use for accessing files stored in S3. Endpoint or region are required for S3 support.',1,0,'text',121,'AWS S3 Region',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (124,'AWS_S3_Default_Bucket','Default bucket for LORIS to use for accessing files in S3.',1,0,'text',121,'AWS S3 Default Bucket',3);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (125,'useEEGBrowserVisualizationComponents','Whether to enable the visualization components on the EEG Browser module',1,0,'boolean',39,'Enable the EEG Browser components',4);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (126,'createVisit','Enable visit creation in the imaging pipeline',1,0,'boolean',69,'Enable visit creation',11);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (127,'default_project','Default project used when creating scan candidate or visit',1,0,'text',69,'Default project',12);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (128,'default_cohort','Default cohort used when creating scan visit',1,0,'text',69,'Default cohort',13);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (129,'UserMaximumDaysInactive','The maximum number of days since last login before making a user inactive.',1,0,'text',1,'Maximum Days Before Making User Inactive',30);
INSERT INTO `ConfigSettings` (`ID`, `Name`, `Description`, `Visible`, `AllowMultiple`, `DataType`, `Parent`, `Label`, `OrderNumber`) VALUES (130,'EEGUploadIncomingPath', 'Path to the upload directory for incoming EEG studies', 1, 0, 'text', 26, 'EEG Incoming Directory', 15);
UNLOCK TABLES;
SET FOREIGN_KEY_CHECKS=1;
