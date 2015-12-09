#!/usr/bin/env python

##########################################################################################
### 23/01/2011 DGF - creato                                                            ###
### 09/12/2015 DGF - Miglioramento gestione eccezioni quando non e' presente sul F.S.  ###
###                  delle CA la crl cercata                                           ###
##########################################################################################

######################
### import modules ###
######################

import datetime
import logging
import time
import re
import getopt
import os
import pprint
import subprocess
import sys
import tempfile
import configparser
import smtplib
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from datetime import timedelta

#########################################
### dichiarazione costanti simboliche ###
#########################################

SCRIPT_VERSION = "4.8"
PATH_HOME = "/opt/CHECK_CRL_FS/"
PATH_LOG = PATH_HOME+"Log/"
PATH_WORK = PATH_HOME+"Work/"
CONFIG_FILE = PATH_HOME+"Config/Config.cfg"
TEXT_SEND_FILE = PATH_WORK+"body_mail.txt"
RECIPIENT = 'xxxxxx@xxxxxxxx.com'
RECIPIENT1 = 'xxxxx@xxxx.com'
RECIPIENT2 = 'xxxxxxxxx@xxxxxx.com'
RECIPIENT3 = 'xxxxxxxxxxx@xxxxxxxxx.com'
RECIPIENT4 = 'xxxxxxxx@xxxxxxxxxx.xx'
MSG_FROM = 'xxxx_xxx@xxxxxxxx.com'
MAILSERVER = '10.0.0.9'
SERVER_SNMP = '10.0.0.10'
TYPE_HTTP = 'http'
TYPE_LDAP = 'ldap'

############################
### definizione funzioni ###
############################

def SendMail():
    """ funzione che mi permette di mandare mail """

    fp = open(TEXT_SEND_FILE,'rb')
    msg = MIMEText(fp.read(),'plain','utf-8')
    fp.close()
    msg['Subject'] = '[CRL CHECK] CRL publication failed'
    msg['From'] = MSG_FROM
    msg['To'] = RECIPIENT
    msg['To'] = RECIPIENT1
    msg['To'] = RECIPIENT2
    msg['To'] = RECIPIENT3
    msg['To'] = RECIPIENT4
    s = smtplib.SMTP(MAILSERVER)
    s.sendmail('XXXXXX@xxxxxxx.com', [RECIPIENT,RECIPIENT1,RECIPIENT2,RECIPIENT3,RECIPIENT4], msg.as_string())
    s.quit()
    ### Cancello il file body necessario a spedire la mail ###
    try:
        tf = open(TEXT_SEND_FILE,'r')
        tf.close()
        os.remove(TEXT_SEND_FILE)

    except IOError:
        sys.exit()


def get_crl_http(crl_http, logger):
    """ funzione per prendere la crl da File System """

    try:
        crl_lastupdate = subprocess.check_output(["/usr/bin/openssl", "crl", "-inform", "DER", "-noout", "-lastupdate", "-in", crl_http])
    except (subprocess.CalledProcessError, OSError) as b:
        logger.error("errore nell'aprire crl http"+str(b))
        fp = open(TEXT_SEND_FILE,'a')
        msg01 = "Errore di aperture file http "
        logger.error(msg01)
        fp.write(msg01+"\n")
        fp.write("Si prega di controllare la pubblicazione http "+crl_http)
        fp.close()
        SendMail()
        ### Mando trap a  nagios ##
        #os.system('echo "ldap2*invio trap check_crl-X.X.py*2*La crl '+name_section+' connessione mancata su server '+crl_http+'"|/usr/local/nagios/bin/send_nsca -H '+SERVER_SNMP+' -d "*" -c /usr/local/nagios/bin/send_nsca.cfg')

    try:
        lastupdate_http = crl_lastupdate.strip().decode('utf-8').split("=")

    except (NameError, UnboundLocalError) as last:
        logger.error("problemi con file http :"+str(last))

    try:
        crl_creation_time = datetime.datetime.strptime(lastupdate_http[1],"%b %d %H:%M:%S %Y GMT")

    except (IndexError, UnboundLocalError) as crl_creation:
        logger.error("problemi con file http :"+str(crl_creation))

    return crl_creation_time


def get_crl_ldap(path_ldap,ldapserver,ldapport,logger,ldap_user,ldap_password):
    """ funzione per prendere la crl da ldap """

    ### verifico che la connessione a ldap sia andata a buon fine ###
    try:
        exec_ldap_q = subprocess.check_output(["/usr/bin/ldapsearch", "-T", "-D", ldap_user, "-w", ldap_password, "-t", "-h", ldapserver, "-p", ldapport, "-b", path_ldap, "objectClass=*", "certificaterevocationlist"],stderr=subprocess.STDOUT)
        ###exec_ldap_q = subprocess.check_output(["/usr/bin/ldapsearch", "-T", "-D", 'ldap_user', "-w", 'ldap_password', "-t", "-h", ldapserver, "-p", ldapport, "-b", path_ldap, "objectClass=*", "certificaterevocationlist"],stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as e:
        logger.error("errore di connessione con il server ldap "+str(e))
        fp = open(TEXT_SEND_FILE,'a')
        msg1 = "Errore di connessione al server ldap "
        logger.error(msg1)
        fp.write(msg1+"\n")
        fp.write("Si prega di controllare il server ldap "+ldapserver)
        fp.close()
        SendMail()
        ### Mando trap a  nagios ##
        os.system('echo "ldap2*invio trap check_crl-X.X.py*2*La crl '+name_section+' connessione mancata su server '+ldapserver+'"|/usr/local/nagios/bin/send_nsca -H '+SERVER_SNMP+' -d "*" -c /usr/local/nagios/bin/send_nsca.cfg')

    try:
        file_tmp_q = exec_ldap_q.split()

    except (NameError, UnboundLocalError) as file_tmp:
        logger.error("Non riesco a fare lo split della query ldapsearch : "+str(file_tmp))

    try:
        file_q_ldap_tmp = file_tmp_q[len(file_tmp_q)-1]

    except (IndexError, UnboundLocalError) as file_q_ldap:
        logger.error("problema a gestire la query ldap "+str(file_q_ldap))

    try:
        crl_lastupdate_ldap = subprocess.check_output(["/usr/bin/openssl", "crl", "-inform", "DER", "-noout", "-lastupdate", "-in", file_q_ldap_tmp])

    except (subprocess.CalledProcessError, UnboundLocalError) as a:
        logger.error("errore openssl "+str(a))

    try:
        lastupdate_ldap = crl_lastupdate_ldap.strip().decode('utf-8').split("=")

    except (ValueError, UnboundLocalError) as a_lastupdate_ldap:
        logger.error("Non riesco a trovare il lastupdate "+str(a_lastupdate_ldap))
        ### Mando trap nagios ##
        os.system('echo "XXXXXX*invio trap check_crl-X.X.py*2*La crl '+name_section+' connessione mancata su server '+ldapserver+'"|/usr/local/nagios/bin/send_nsca -H '+SERVER_SNMP+' -d "*" -c /usr/local/nagios/bin/send_nsca.cfg')
        ###os.system('echo "ldap2*invio trap check_crl-X.X.py*2*La crl '+name_section+' errore openssl '"|/usr/local/nagios/bin/send_nsca -H '+SERVER_SNMP+' -d "*" -c /usr/local/nagios/bin/send_nsca.cfg')

    try:
        crl_creation_time = datetime.datetime.strptime(lastupdate_ldap[1],"%b %d %H:%M:%S %Y GMT")

    except (IndexError, UnboundLocalError) as crl_creation_time:
        logger.error("errore con la formattazione della data "+str(crl_creation_time))

    ### Cancello il file temporaneo prodotta dall'ldapsearch ###
    try:
        tf = open(file_q_ldap_tmp,'r')
        tf.close()
        os.remove(file_q_ldap_tmp)

    except IOError:
        logger.error("File ldapsearch temporaneo non presente")

    return crl_creation_time


def check_crl(crl_creat_time, emis, name_section, logger, type, description, info_http_ldap):
    """ funzione che mi permette di verificare se la crl e' valida o no """

    dd = timedelta(seconds = int(emis))
    crl_creation_plus_delta = crl_creat_time + dd
    today = datetime.datetime.now()
    delta = today - crl_creat_time
    if delta > dd:
        fp = open(TEXT_SEND_FILE,'a')
        msg = type+" CRL publication %s con PKI instance : %s has Expired (on %s)\n" % (name_section,description,crl_creation_plus_delta)
        logger.error(msg)
        fp.write(msg+"\n")
        fp.write("url http o base DN ldap : "+info_http_ldap)
        fp.close()
        SendMail()
        os.system('echo "ldap2*invio trap check_crl-X.X.py*2*La crl '+name_section+' ha fallito la pubblicazione su '+type+'"|/usr/local/nagios/bin/send_nsca -H '+SERVER_SNMP+' -d "*" -c /usr/local/nagios/bin/send_nsca.cfg')

    else:
        msg = "Publication of "+type+" CRL %s OK valid time from the beginning %s and will expire (on %s)" % (name_section,delta, crl_creation_plus_delta)
        logger.info(msg)


def main():
    """ funzione start """
    SYSTEM_DATE=time.strftime("%Y%m%d")
    LOG_FILENAME = PATH_LOG+"check_crl-"+SCRIPT_VERSION+"-"+SYSTEM_DATE+".log"

    ### definizione dell'oggetto logger che serve a gestire i log ###
    logger = logging.getLogger("check_crl-"+SCRIPT_VERSION+".py")
    hdlr = logging.FileHandler(LOG_FILENAME)
    FORMAT = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
    hdlr.setFormatter(FORMAT)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)

    ### verifica presenza file di configurazione ###
    try:
        f = open(CONFIG_FILE,'r')
        logger.info("Verifica file di configurazione andata a buon fine")
        f.close()

    except IOError:
        logger.error("Il file di configurazione non esiste, verificare. Esco!")
        sys.exit()

    ### definizione dell'oggetto parser per la lettura del file di configurazione ###
    parser = configparser.ConfigParser()
    parser.read(CONFIG_FILE)

    ### ciclo principale per la lettura ###
    for name_section in parser.sections():
        print(name_section)

        ### verifico se prendere la crl da http ###
        if parser.getboolean(name_section,'pubblication_http') == True:
            try:
                crl_creation_time = get_crl_http(parser.get(name_section,'link_to_crl'), logger)
                logger.info("Verifica per crl http "+parser.get(name_section,'link_to_crl'))
                check_crl(crl_creation_time, parser.get(name_section,'expiration_date'), name_section, logger,TYPE_HTTP, parser.get(name_section,'pki_instance'), parser.get(name_section,'http_crl_dp'))

            except (NameError, UnboundLocalError) as crl_creation_http:
                logger.error("errore valorizzazione variabile crl_creation_time : "+str(crl_creation_http))

        else:
            logger.info("La crl : "+name_section+"  non e' pubblicata su ldap")

        ### verifico se prendere la crl da ldap ###
        if parser.getboolean(name_section,'pubblication_ldap') == True:
            try:
                crl_creation_time = get_crl_ldap(parser.get(name_section,'path_ldap'),parser.get(name_section,'ldap_server'),parser.get(name_section,'ldap_port'),logger,parser.get(name_section,'ldap_user'),parser.get(name_section,'ldap_password'))
                logger.info("Verifica per crl ldap "+parser.get(name_section,'path_ldap'))

            except (NameError, UnboundLocalError) as sdf:
                logger.error("problema collegamento ldap server "+str(sdf))

            try:
                check_crl(crl_creation_time, parser.get(name_section,'expiration_date'), name_section, logger, TYPE_LDAP, parser.get(name_section,'pki_instance'), parser.get(name_section,'path_ldap'))

            except (NameError, UnboundLocalError) as qwer:
                logger.error("problema connessione ldap server",name_section+"  "+str(qwer))

        else:
            logger.info("La crl : "+name_section+" non e' pubblicata su ldap")


############
### MAIN ###
############

if __name__ == "__main__":
    main()
