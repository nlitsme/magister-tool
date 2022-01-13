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
      --allejaren           output cijfers of all years
      --rooster, -r         output rooster
      --absenties, -A       output absenties
      --studiewijzer, -s    output studiewijzer
      --opdrachten, -O      output opdrachten/activiteiten/projecten
      --get GET             get data from magister
      --config CONFIG       specify configuration file.
      --cache CACHE         specify the magister access-token cache file.
      --verbose
      --xsrftoken XSRFTOKEN
      --accesstoken ACCESSTOKEN
      --username USERNAME
      --password PASSWORD
      --authcode AUTHCODE
      --schoolserver SCHOOLSERVER
      --magisterserver MAGISTERSERVER


TODO
====

 * Optie om rooster van eerdere datums terug te kijken.



Author: Willem Hengeveld <itsme@xs4all.nl>

