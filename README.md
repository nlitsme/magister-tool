Magister school tool
====================

Tool to quickly get an overview of all relevant information from your school's magister account.

Magister is a service used by many dutch schools through which both parents and students can access
schedules, results, study programs etc.

Requirements
============

Needs python v3.8.

Configuration
=============

Create a file named `.magisterrc` in your HOME directory with the following:

    school=schoolname.magister.net
    user=myloginname
    pass=MySecretPassword


Usage
=====

    Usage: magister.py [options]

    Magister info dump

    optional arguments:
      -h, --help            show this help message and exit
      --debug, -d           print all intermediate steps
      --all, -a             output all info
      --cijfers, -c         output cijfers
      --rooster, -r         output rooster
      --absenties, -A       output absenties
      --studiewijzer, -s    output studiewijzer
      --config CONFIG       specify configuration file.
      --verbose
      --username USERNAME
      --password PASSWORD
      --authcode AUTHCODE
      --schoolserver SCHOOLSERVER
      --magisterserver MAGISTERSERVER


Author: Willem Hengeveld <itsme@xs4all.nl>

