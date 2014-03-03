#!/bin/bash

#
# This will:
#   1. Install PEAR libraries
#   2. Set up the Loris DB schema
# This will only install the database components and Loris config file.
#

CWD=`pwd`
RootDir=`dirname $CWD`

# Banner
cat <<BANNER

---------------------------------------------------------------------
                   LORIS Installation Script
---------------------------------------------------------------------

BANNER

# Check that bash is being used
if $BASH ; then
    echo "Please use bash shell. Run the install script as command: ./install.sh"
    exit 2
fi

# Check that we're running in the proper directory structure.
if [ ! -f ../SQL/0000-00-00-schema.sql ] ; then
    echo "Could not find schema file; make sure the current directory is in tools/ under the distribution."
    exit 2
fi

# Must be run interactively.
if ! test -t 0 -a -t 1 -a -t 2 ; then
    echo "This installation program should be run interactively."
    exit 2
fi

# Create some subdirectories, if needed.
mkdir -p logs ../project ../project/tables_sql



#
# Configure logging.
# From now on, STDOUT and STDERR are sent to both the terminal AND a logfile in logs/
#
START=`date "+%Y-%m-%dT%H:%M:%S"`
LOGDIR="logs"
LOGFILE="logs/install-$START.log"
LOGPIPE=/tmp/pipe.$$
mkfifo -m 700 $LOGPIPE
trap "rm -f $LOGPIPE" EXIT
tee <$LOGPIPE capt &
exec 1>$LOGPIPE 2>&1


if [ ! -w $LOGDIR ] ; then
	echo "The logs directory is not writeable. You will not have an automatically generated report of your installation." 
	while true; do
    		read -p "Do you still want to continue? [yn] " yn
    		case $yn in
		        [Yy]* )
				break;;
		        [Nn]* )
            			echo "Aborting installation."
				exit 2;
	         * ) echo "Please enter 'y' or 'n'."
    		esac
	done;
fi

echo "LORIS Installation Script starting at $START"
echo "The log for this session will be stored in file $CWD/$LOGFILE"

if [ -f ../project/config.xml ]; then
    echo "Loris appears to already be installed. Aborting."
    exit 2;
fi

if [[ -n $(which php) ]]; then
    echo ""
    echo "PHP appears to be installed."
else
    echo ""
    echo "PHP does not appear to be installed. Aborting."
    exit 2;
fi

if [[ -n $(which pear) ]]; then
    echo ""
    echo "PEAR appears to be installed."
else
    echo ""
    echo "PEAR does not appear to be installed. Aborting."
    exit 2;
fi

cat <<QUESTIONS

Please answer the following questions. You'll be asked:

  a) A name for the MySQL Database. This should be
     a simple identifier such as "Loris" or "Abc_Def".
     This database will be created later on.

  b) The hostname for the machine where the MySQL server will run on
     (this is where we'll create the database).

  c) The MySQL username that the Loris system will use to connect
     to this server and database; this MySQL account will be
     created later on.

  d) The password for this username (it will be set later on).

  e) Credentials of an existing root MySQL account to install the
     default schema. This will only be used once, to create and
     populate the default tables, and to grant privileges to the
     newly created MySQL user in part c).

  f) Another password for the 'admin' account of the Loris DB
     (it will also be set later on).


Validations are POORLY implemented here; if you make a mistake
answering these questions, kill the script with CTRL-C and
start it again.

QUESTIONS


while true; do
	read -p "What is the database name? " mysqldb
	case $mysqldb in
		"" )
			read -p "What is the database name? " mysqldb
			continue;;
		* ) 
			break;;
	esac
done;

while true; do 
        read -p "Database host? " mysqlhost
        case $mysqlhost in
                "" )
                        read -p "Database host? " mysqlhost
                        continue;;
                * ) 
                        break;;
        esac
done;

while true; do 
        read -p "What MySQL user will Loris connect as? " mysqluser
        case $mysqluser in
                "" )
                        read -p "What MySQL user will Loris connect as? " mysqluser
                        continue;;
                * ) 
                        break;;
        esac
done;

stty -echo

while true; do 
        read -p "What is the password for MySQL user '$mysqluser'? " mysqlpass
        case $mysqlpass in
                "" )
                        read -p "What is the password for MySQL user '$mysqluser'? " mysqlpass
                        continue;;
                * ) 
                        break;;
        esac
done;

stty echo ; echo ""
stty -echo

while true; do 
        read -p "Enter Loris admin user's password: " lorispass
        case $lorispass in
                "" )
                        read -p "Enter Loris admin user's password: " lorispass
                        continue;;
                * ) 
                        break;;
        esac
done;

stty echo ; echo ""

while true; do 
        read -p "Root MySQL username: " mysqlrootuser
        case $mysqlrootuser in
                "" )
                        read -p "Root MySQL username: " mysqlrootuser
                        continue;;
                * ) 
                        break;;
        esac
done;

stty -echo

while true; do 
        read -p "Root MySQL password: " mysqlrootpass
        case $mysqlrootpass in
                "" )
                        read -p "Root MySQL password: " mysqlrootpass
                        continue;;
                * ) 
                        break;;
        esac
done;

stty echo


echo ""
echo "Attempting to create the MySQL database '$mysqldb' ..."
echo ""
echo "CREATE DATABASE $mysqldb" | mysql -h$mysqlhost --user=$mysqlrootuser --password="$mysqlrootpass" -A > /dev/null 2>&1
MySQLError=$?;
if [ $MySQLError -ne 0 ] ; then
    echo "Could not connect to database with the root user provided.";
    while true; do
    	read -p "Would you like to try one last time? [yn] " yn
    	case $yn in
        	[Yy]* )
			echo "Attempting to create the MySQL database '$mysqldb' ..."
			while true; do 
			        read -p "Root MySQL username: " mysqlrootuser
        			case $mysqlrootuser in
                			"" )
			                        read -p "Root MySQL username: " mysqlrootuser
                        			continue;;
		                	* ) 
                			        break;;
        			esac
			done;

			stty -echo

			while true; do 
			        read -p "Root MySQL password: " mysqlrootpass
        			case $mysqlrootpass in
                			"" )
			                        read -p "Root MySQL password: " mysqlrootpass
                        			continue;;
                			* ) 
		        	                break;;
        			esac
			done;

			stty echo
            		break;;
        	[Nn]* ) 
            		echo "Exiting."
			exit 1;;
        	* ) echo "Please enter 'y' or 'n'."
	esac
    done;

    echo "CREATE DATABASE $mysqldb" | mysql -h$mysqlhost --user=$mysqlrootuser --password="$mysqlrootpass" -A > /dev/null 2>&1
    MySQLError=$?;
    if [ $MySQLError -ne 0 ] ; then
        echo "Could not connect to database with the root user provided.";
        exit 1;
    fi

fi



echo ""
echo "Attempting to create and grant privileges to MySQL user '$mysqluser'@'localhost' ..."
echo ""
echo "GRANT UPDATE,INSERT,SELECT,DELETE ON $mysqldb.* TO '$mysqluser'@'localhost' IDENTIFIED BY '$mysqlpass' WITH GRANT OPTION" | mysql $mysqldb -h$mysqlhost --user=$mysqlrootuser --password="$mysqlrootpass" -A > /dev/null 2>&1
MySQLError=$?;
if [ $MySQLError -ne 0 ] ; then
    echo "Could not connect to database with the root user provided.";
    exit 1;
fi



echo ""
echo "Creating database tables from schema."
echo ""
mysql $mysqldb -h$mysqlhost --user=$mysqlrootuser --password="$mysqlrootpass" -A 2>&1 < ../SQL/0000-00-00-schema.sql
echo "Updating Loris admin user's password."
mysql $mysqldb -h$mysqlhost --user=$mysqluser --password="$mysqlpass" -A -e "UPDATE users SET Password_MD5=CONCAT('aa', MD5('aa$lorispass')) WHERE ID=1"



echo ""
echo "Creating config file."
echo ""
sed -e "s/%HOSTNAME%/$mysqlhost/g" \
    -e "s/%USERNAME%/$mysqluser/g" \
    -e "s/%PASSWORD%/$mysqlpass/g" \
    -e "s/%DATABASE%/$mysqldb/g" \
    -e "s#%LORISROOT%#$RootDir/#g" \
    < ../docs/config/config.xml > ../project/config.xml


echo ""
echo "Setting up templates_c directory."
echo ""
mkdir -p  $RootDir/php/smarty/templates_c
chmod 777 $RootDir/php/smarty/templates_c


while true; do
    read -p "Would you like to install PEAR libraries (affects system files)? [yn] " yn
    case $yn in
        [Yy]* )
            echo "Installing PEAR libraries (may prompt for sudo password)."
            sudo pear upgrade-all >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Benchmark >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Config >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install File_Archive >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install HTML_Common >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install HTML_QuickForm >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear config-set preferred_state beta >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install HTML_QuickForm2 >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Mail >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Mail_Mime >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Net_SMTP >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Net_Socket >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install OLE >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Pager >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install PhpDocumentor >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Spreadsheet_Excel_Writer >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install Structures_Graph >> logs/install-`date +%Y-%m-%d`.log 2>&1
            sudo pear install XML_Parser >> logs/install-`date +%Y-%m-%d`.log 2>&1
            break;;
        [Nn]* ) 
            echo "Not installing PEAR libraries."
            break;;
        * ) echo "Please enter 'y' or 'n'."
   esac
done;


while true; do
    read -p "Would you like to automatically create/install apache config files? [yn] " yn
    case $yn in
        [Yy]* )
            read -p "Enter project name: " projectname
            if [ -f /etc/apache2/sites-available/$projectname ]; then
                echo "Apache appears to already be configured for $projectname. Aborting\n"
                exit 1
            fi;

            # Need to pipe to sudo tee because > is done as the logged in user, even if run through sudo
            sed -e "s#%LORISROOT%#$RootDir/#g" \
                -e "s#%PROJECTNAME%#$projectname#g" \
                < ../docs/config/apache2-site | sudo tee /etc/apache2/sites-available/$projectname > /dev/null
            sudo a2dissite default
            sudo a2ensite $projectname
            break;;
        [Nn]* )
            echo "Not configuring apache."
            break;;
         * ) echo "Please enter 'y' or 'n'."
    esac
done;

echo "Installation complete."



