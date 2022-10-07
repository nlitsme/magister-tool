#!/usr/bin/python3
import re
import urllib.request
import urllib.parse
import http.cookiejar
import json
from datetime import datetime, timezone, timedelta
import binascii

def dehtml(html):
    """
    convert html to somewhat readable text.
    """
    html = re.sub(r"</p>|<br>", "\n", html)
    html = re.sub(r"</?\w+[^>]*>", "", html)
    html = re.sub(r"&nbsp;", " ", html)
    html = re.sub(r"&gt;", ">", html)
    html = re.sub(r"&lt;", "<", html)
    html = re.sub(r"&amp;", "&", html)
    return html

def datum(ts):
    """
    Strip the date's to a more reasonable string.
    """
    if not ts:
        return "?"
    if m := re.split(r"[-T:Z.]", ts):
        y, m, d, H, M, S, us = map(int, m[:-1])
        localtz = datetime(y, m, d, H, M, S).astimezone().tzinfo
        t = datetime(y, m, d, H, M, S, tzinfo=timezone.utc)
        t = t.astimezone(localtz)
        return f"{t:%Y-%m-%d %H:%M:%S}"

    return ts[:19]

def utctime(ts):
    if m := re.split(r"[-T:Z.]", ts):
        y, m, d, H, M, S = map(int, m[:-1])
        return datetime(y, m, d, H, M, S, tzinfo=timezone.utc)

def ymd(years=0, days=0, weeks=0):
    t = datetime.now()
    if years:
        t += timedelta(days=365*years)
    elif days:
        t += timedelta(days=days)
    elif weeks:
        t += timedelta(weeks=weeks)
    return "%04d-%02d-%02d" % (t.year, t.month, t.day)

class Magister:
    """
    object encapsulating all magister functionality.
    """
    def __init__(self, args):
        self.args = args
        self.xsrftoken = args.xsrftoken
        self.access_token = args.accesstoken
        self.magisterserver = args.magisterserver
        self.schoolserver = args.schoolserver
        self.cj = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.cj)]
        if args.debug:
            handlers.append(urllib.request.HTTPSHandler(debuglevel=1))
        self.opener = urllib.request.build_opener(*handlers)

    def logprint(self, *args):
        if self.args.debug:
            print(*args)

    def httpreq(self, url, data=None):
        """
        Generic http request function.
        Does a http-POST when the 'data' argument is present.

        Adds the nesecesary xsrf and auth headers.
        """
        self.logprint(">", url)
        hdrs = { }
        if data and type(data)==str:
            data = data.encode('utf-8')
        if data and data[:1] in (b'{', b'['):
            hdrs["Content-Type"] = "application/json"
        if self.xsrftoken:
            hdrs["X-XSRF-TOKEN"] = self.xsrftoken
        if self.access_token:
            hdrs['Authorization'] = 'Bearer ' + self.access_token
        req = urllib.request.Request(url, headers=hdrs)
        kwargs = dict()
        if data:
            kwargs["data"] = data
        try:
            response = self.opener.open(req, **kwargs)
        except urllib.error.HTTPError as e:
            self.logprint("!", str(e))
            response = e

        data = response.read()
        if response.headers.get("content-type", '').find("application/json")>=0:
            js = json.loads(data)
            self.logprint(js)
            self.logprint()
            return js
        self.logprint(data)
        self.logprint()
        return data

    def extractxsrf(self):
        """
        Find the XSRF token in the CookieJar
        """
        for c in self.cj:
            if c.name == "XSRF-TOKEN":
                return c.value

    def httpredirurl(self, url, data=None):
        """
        request 'url', obtaining both the final result, and final redirected-to URL.
        """
        self.logprint(">", url)
        hdrs = { }
        if data and data[:1] in (b'{', b'['):
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, headers=hdrs)
        kwargs = dict()
        if data:
            kwargs["data"] = data
        response = self.opener.open(req, **kwargs)
        data = response.read()

        self.logprint(data)
        self.logprint()

        return response.url, data

    def extract_account_url(self, html):
        """
        Find the name of the account-XXXXX.js file.
        """
        if m := re.search(r'js/account-\w+\.js', html):
            return f"https://{self.magisterserver}/{m.group(0)}"

    def extract_authcode(self, js):
        """
        Extract the authCode from the 'account-XXXXX.js' file.

        This function handles only one of the type of account.js files.

        The other kind is not handled (yet), which stores the parts of the authcode
        string in separate variables and then using those vars instead of literal strings in the 'n' Array.
        """
        if m := re.search(r'\([nr]=\["([0-9a-f",]+?)"\],\["([0-9",]+)"\]\.map', js):
            codes = m.group(1).split('","')
            idxes = [int(_) for _ in m.group(2).split('","')]

            return "".join(codes[_] for _ in idxes)
        
        print("Did not find encoded authcode, using default!")

        return self.args.authcode

    def extract_oidc_config(self, js):
        """
        Decode the javascript containing the oidc config.
        """
        cfg = dict()
        for line in js.split("\r\n"):
            if not line: continue
            if m := re.match(r'\s*(\w+):\s*(.*),?$', line):
                key, value = m.groups()
                value = re.sub(r'\' \+ window\.location\.hostname', f"{self.schoolserver}'", value)
                value = re.sub(r'\' \+ \'', "", value)
                if value == 'false':
                    value = False
                elif value == 'true':
                    value = True
                elif m := re.match(r'\'(.*)\',?$', value):
                    value = m.group(1)
                cfg[key] = value;

        return cfg

    def login(self, username, password):
        """
        Authenticate to the magister server using username and password.
        """
        openidcfg = self.httpreq(f"https://{self.magisterserver}/.well-known/openid-configuration")
        if not openidcfg:
            print("could not get magister openid config")
            return
        oidcjs = self.httpreq(f"https://{self.schoolserver}/oidc_config.js")
        if not oidcjs:
            print("could not get school config")
            return
        oidccfg = self.extract_oidc_config(oidcjs.decode('utf-8'))

        params = dict(
            client_id= oidccfg["client_id"],         # f"M6-{self.schoolserver}"
            redirect_uri= oidccfg["redirect_uri"],   # f"https://{self.schoolserver}/oidc/redirect_callback.html",
            response_type= oidccfg["response_type"], # "id_token token",
            scope= "openid profile",
            state= "11111111111111111111111111111111",
            nonce= "11111111111111111111111111111111",
            acr_values= oidccfg["acr_values"],       # f"tenant:{self.schoolserver}",
        )

        self.logprint("\n---- auth ----")

        # sets the XSRF-TOKEN cookie
        sessionurl, html = self.httpredirurl(openidcfg["authorization_endpoint"] + "?" + urllib.parse.urlencode(params))
        # this causes three redirects, all of which provide information we need later:
        #   1) https://{self.magisterserver}/connect/authorize
        #   2) https://{self.magisterserver}/Account/Login                -> set: Magister.Identities.XSRF
        #   3) https://{self.magisterserver}/account/login ? sessionid    -> set: XSRF-TOKEN,  and account-XXX.js

        self.xsrftoken = self.extractxsrf()
        if self.args.verbose:
            print(f"-> xsrf = {self.xsrftoken}")

        self.logprint("\n---- account.js ----")
        accountjs_url = self.extract_account_url(html.decode('utf-8'))
        if not accountjs_url:
            print("could not get account.js url")
            return
        actjs = self.httpreq(accountjs_url)

        authcode = self.extract_authcode(actjs.decode('utf-8'))
        if self.args.verbose:
            print("-> authcode =", authcode)

        # extract sessionid from redirect-url
        qs = sessionurl[sessionurl.find('?')+1:]
        sessioninfo = urllib.parse.parse_qs(qs)

        self.logprint(sessioninfo)
        self.logprint()

        # todo - handle cp?
        #https://{self.magisterserver}/challenges/change-password

        self.logprint("\n---- current ----")
        d = dict(
            sessionId= sessioninfo["sessionId"][0],  # from redirect
            returnUrl= sessioninfo["returnUrl"][0],
            authCode= authcode,
        )
        r = self.httpreq(f"https://{self.magisterserver}/challenges/current", json.dumps(d))
        # r.action == username
        # r.tenantname = ...

        d["username"] = username

        self.logprint("\n---- username ----")
        r = self.httpreq(f"https://{self.magisterserver}/challenges/username", json.dumps(d))
        # r.action == password  || 
        #                       || r.error = 'InvalidUsername'
        # r.username = ...      
        if r['error']:
            print("ERROR '%s'" % r['error'])
            return


        d["password"] = password

        self.logprint("\n---- password ----")
        r = self.httpreq(f"https://{self.magisterserver}/challenges/password", json.dumps(d))
        # r.action == None    || r.action == "changepassword"  || r.action == None
        # r.redirectURL= ...  || r.redirectURL==None           || r.redirectURL==None
        #                                                      || r.error == "InvalidUsernameOrPassword"

        if not r['redirectURL'] or r['error']:
            if r['action']:
                print("'%s' requested -> visit website" % r['action'])
                return
            print("ERROR '%s'" % r['error'])
            return

        self.logprint("\n---- callback ----")
        url, html = self.httpredirurl(f"https://{self.magisterserver}" + r["redirectURL"])

        _, qs = url.split('#', 1)
        d = urllib.parse.parse_qs(qs)
        self.logprint(d)
        self.access_token = d["access_token"][0]
        if self.args.verbose:
            print(f" -> access = {self.access_token}")

        return True

    def printsessioninfo(self):
        """
        todo
        """
        #d = self.req('sessions', 'current')
        #d = self.getlink(d["links"]["account"])
        #d = self.httpreq(f"https://{self.magisterserver}/connect/userinfo")

    def req(self, *args):
        """
        Generic 'school' request method, converts and concats all argments automatically.
        With the last argument optionally a dict, when a querystring is needed.
        """
        tag = []
        for v in args:
            if type(v)==str and re.match(r'^[a-z]+$', v):
                tag.append(v)

        self.logprint(f"\n---- {'.'.join(tag)} ---")

        qs = ""
        if args and type(args[-1])==dict:
            querydict = args[-1]
            args = args[:-1]
            qs = "?" + urllib.parse.urlencode(querydict)

        path = "/".join(str(_) for _ in args)
        return self.httpreq(f"https://{self.schoolserver}/api/{path}{qs}")

    def getlink(self, link):
        """
        request the link specified in the 'link' dictionary.
        """
        if not link:
            return
        return self.httpreq(f"https://{self.schoolserver}{link['href']}")


def printcijfers(c):
    print("-- cijfers --")
    for item in c["items"]:
        print("%s - %-3s %-6s x %3.1f - %s" % (datum(item["ingevoerdOp"]), item["vak"]["code"], item["waarde"], item["weegfactor"], item["omschrijving"]))

def printopdrachten(x):
    print("-- opdrachten --")
    for item in x["Items"]:
        voor = datum(item["InleverenVoor"])
        op = datum(item["IngeleverdOp"])
        print("%-19s ; %-19s  ; %-4s - %s" % (voor, op, item["Vak"], item["Titel"]))
        print(dehtml(item["Omschrijving"]))

def printaanmeldingen(x):
    print("-- aanmeldingen --")
    for item in x["Items"]:
        print("%s ; %s - (%s) %s" % (datum(item["Start"]), datum(item["Einde"]), item["Lesperiode"], item["Studie"]["Omschrijving"]))

def printprojecten(x):
    print("-- projecten --")
    for item in x["Items"]:
        print("%s ; %s - %s" % (datum(item["Van"]), datum(item["TotEnMet"]), item["Titel"]))

def printabsenties(x):
    print("-- absentiesactiviteiten --")
    for item in x["Items"]:
        print("%s ; %s - %s ; %s" % (datum(item["Start"]), datum(item["Eind"]), item["Omschrijving"], item["Afspraak"]["Omschrijving"]))

def printactiviteiten(x):
    print("-- activiteiten --")
    for item in x["Items"]:
        print("%s ; %s - %s" % (datum(item["ZichtbaarVanaf"]), datum(item["ZichtbaarTotEnMet"]), item["Titel"]))

def infotstr(t):
    typenames = ["", "hw", "T!", "TT", "SO", "MO", "in", "aa"]
    if 0 <= t < len(typenames): return typenames[t]
    return "??"

def printafspraken(x):
    print("-- afspraken --")
    for item in x["Items"]:
        """
        Type: 1:"Persoonlijk", 2:"Algemeen", 3:"Schoolbreed", 4:"Stage", 5:"Intake", 6:"Roostervrij", 7:"Kwt", 8:"Standby", 9:"Blokkade",
             10:"Overig", 11:"BlokkadeLokaal", 12:"BlokkadeKlas", 13:"Les", 14:"Studiehuis", 15:"RoostervrijeStudie", 16:"Planning",
             101:"Maatregelen", 102:"Presenties", 103:"ExamenRooster"
        Status 1:automatisch, 3:gewijziged, 7:afgesloten. ...
        Infotype 1: 'Huiswerk'  2:'Proefwerk', 3:Tentamen, 4:SchriftelijkeOverhoring, 5:MondelingeOverhoring, 6:Informatie, 7:Aantekening
        """

        print("%s ; %s <%2s> %s ; %s" % (datum(item["Start"]), datum(item["Einde"]), infotstr(item["InfoType"]), item["Lokatie"], item["Omschrijving"]))
        if item["Inhoud"]:
            print(dehtml(item["Inhoud"]))

def printwijzigingen(x):
    print("-- roosterwijzigingen --")
    for item in x["Items"]:
        print("%s ; %s <%2s> %s ; %s" % (datum(item["Start"]), datum(item["Einde"]), infotstr(item["InfoType"]), item["Lokatie"], item["Omschrijving"]))
        if item["Inhoud"]:
            print(dehtml(item["Inhoud"]))

def printstudiewijzer(x):
    print("-- studiewijzer %s - %s ; %s" % (datum(x["Van"]), datum(x["TotEnMet"]), x["Titel"]))


def print_jaar_cijfers(mg, v):
    for item in v["items"]:
        info = mg.getlink(item['links'].get('werkinformatie'))
        afgenomenop = info.get("afgenomenOp") if info else None
        weegfactor = info.get('weegfactor', '') if info else ''
        weegfactor = f"{weegfactor:3.1f}" if weegfactor else f"k:{item['kolom']['weegfactor']:3.1f}"
        print("%-10s %s - %-8s %-6s x %5s - %s ; %s" % (afgenomenop or "", datum(item["ingevoerdOp"]), item["kolom"]["naam"], item["waarde"], weegfactor, item["kolom"]["omschrijving"], info.get('omschrijving', '') if info else ''))


def loadconfig(cfgfile):
    """
    Load config from .magisterrc
    """
    with open(cfgfile, 'r') as fh:
        txt = fh.read()
    txt = "[root]\n" + txt
    import configparser
    config = configparser.ConfigParser()
    config.read_string(txt)

    return config


def applyconfig(cfg, args):
    """
    Apply the configuration read from .magisterrc to the `args` dictionary,
    which is used to configure everything.
    """
    if not args.username:
        args.username = cfg.get('root', 'user')
    if not args.password:
        args.password = cfg.get('root', 'pass')
    if not args.schoolserver:
        args.schoolserver = cfg.get('root', 'school')
    if not args.authcode:
        args.authcode = cfg.get('root', 'authcode')

def apply_auth_config(cfg, args):
    if args.accesstoken:
        return
    exptime = utctime(cfg.get('root', 'expires'))
    if not exptime:
        return
    now = datetime.now().astimezone(timezone.utc)
    if exptime < now - timedelta(minutes=5):
        return
    args.accesstoken = cfg.get('root', 'accesstoken')

def store_access_token(cache, token):
    now = datetime.now().astimezone()
    f = token.split(".")
    if len(f)>=2:
        j = json.loads(binascii.a2b_base64(f[1]))
        exp = datetime.fromtimestamp(j["exp"], tz=now.tzinfo)
    else:
        exp = now + timedelta(hours=1)

    exp = exp.astimezone(timezone.utc)

    with open(cache, "w+") as fh:
        print(f"expires={exp:%Y-%m-%dT%H:%M:%SZ}", file=fh)
        print(f"accesstoken={token}", file=fh)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Magister info dump')
    parser.add_argument('--debug', '-d', action='store_true', help='print all intermediate steps')
    parser.add_argument('--all', '-a', action='store_true', help='output all info')
    parser.add_argument('--cijfers', '-c', action='store_true', help='output cijfers')
    parser.add_argument('--allejaren', action='store_true', help='output cijfers of all years')
    parser.add_argument('--rooster', '-r', action='store_true', help='output rooster')
    parser.add_argument('--absenties', '-A', action='store_true', help='output absenties')
    parser.add_argument('--studiewijzer', '-s', action='store_true', help='output studiewijzer')
    parser.add_argument('--opdrachten', '-O', action='store_true', help='output opdrachten/activiteiten/projecten')
    parser.add_argument('--get', help='get data from magister')
    parser.add_argument('--config', help='specify configuration file.')
    parser.add_argument('--cache', help='specify the magister access-token cache file.')
    parser.add_argument('--verbose', action='store_true')

    # 'internal' options.
    parser.add_argument('--xsrftoken')
    parser.add_argument('--accesstoken')
    parser.add_argument('--username')
    parser.add_argument('--password')
    parser.add_argument("--authcode")
    parser.add_argument('--schoolserver')
    parser.add_argument('--magisterserver', default='accounts.magister.net')
    args = parser.parse_args()

    if args.all:
        args.cijfers = True
        args.rooster = True
        args.absenties = True
        args.studiewijzer = True
        args.opdrachten = True

    if not args.config:
        import os
        homedir = os.environ['HOME']
        args.config = os.path.join(homedir, ".magisterrc")
    if not args.cache:
        import os
        homedir = os.environ['HOME']
        args.cache = os.path.join(homedir, ".magister_auth_cache")

    try:
        cfg = loadconfig(args.config)

        applyconfig(cfg, args)
    except Exception as e:
        print("config: %s" % e)

    try:
        acfg = loadconfig(args.cache)

        apply_auth_config(acfg, args)
    except Exception as e:
        print("cache: %s" % e)

    mg = Magister(args)

    if not args.accesstoken:
        if not mg.login(args.username, args.password):
            print("Login failed")
            return
        store_access_token(args.cache, mg.access_token)

    if args.get is not None:
        d = mg.req(args.get)
        print(d)
        return

    d = mg.req("account")
    ouderid = d["Persoon"]["Id"]

    k = mg.req("personen", ouderid, "kinderen")

    for kind in k["Items"]:
        print(f"****** {kind['Stamnummer']} {kind['Roepnaam']} {kind['Achternaam']} ({kind['Geboortedatum']}) ******")
        kindid = kind["Id"]
        x = mg.req("personen", kindid, "aanmeldingen")
        printaanmeldingen(x)
        if args.allejaren:
            for meld in x["Items"]:
                v = mg.req('aanmeldingen', meld['Id'], 'cijfers')
                print(f"-- cijfers {meld['Lesperiode']} : {meld['Studie']['Omschrijving']} --")
                print_jaar_cijfers(mg, v)


        if args.cijfers:
            c = mg.req("personen", kindid, "cijfers", "laatste", dict(top=50))
            printcijfers(c)
            if c["links"].get("voortgangscijfers"):   # --> 'aanmeldingen', meldid, 'cijfers'
                v = mg.getlink(c["links"]["voortgangscijfers"])
                print("-- voortgang --")
                print_jaar_cijfers(mg, v)

        if args.opdrachten:
            x = mg.req("personen", kindid, "opdrachten")
            printopdrachten(x)

            x = mg.req("leerlingen", kindid, "projecten")
            printprojecten(x)

            x = mg.req("personen", kindid, "activiteiten")
            printactiviteiten(x)

        if args.absenties:
            x = mg.req("personen", kindid, "absentieperioden")
            print("ap:", x)
            x = mg.req("personen", kindid, "absenties", dict(van=ymd(years=-8), tot=ymd(years=+1)))
            printabsenties(x)

        if args.rooster:
            x = mg.req("personen", kindid, "afspraken", dict(van=ymd(), tot=ymd(weeks=+3)))
            printafspraken(x)

            x = mg.req("personen", kindid, "roosterwijzigingen", dict(van=ymd(), tot=ymd(weeks=+3)))
            printwijzigingen(x)

        x = mg.req("personen", kindid, "mededelingen")
        if x["mededelingen"]["items"]:
            print("md:", x)

        if args.studiewijzer:
            swlist = mg.req("leerlingen", kindid, "studiewijzers")
            for sw in swlist["Items"]:
                switem = mg.req("leerlingen", kindid, "studiewijzers", sw["Id"])
                printstudiewijzer(switem)
                for o in switem["Onderdelen"]["Items"]:
                    #note: 'o' contains the pre-de-htmlized description.

                    z = mg.req("leerlingen", kindid, "studiewijzers", sw["Id"], "onderdelen", o["Id"])
                    print(f"{z['Titel']}\n{dehtml(z['Omschrijving'])}")
                    for b in z["Bronnen"]:
                        uri = b["Uri"] or f"attachment: {b['ContentType']}"
                        print(f" - {b['Naam']} ; {uri}")
                print()
            prjlist = mg.req("leerlingen", kindid, "projecten")
            for prj in prjlist["Items"]:
                prjdetail = mg.req("leerlingen", kindid, "projecten", prj["Id"])
                print("-- projectwijzer ; %s ; %s - %s" % (datum(prj["Van"]), datum(prj["TotEnMet"]), prj["Titel"]))
                for o in prjdetail["Onderdelen"]["Items"]:
                    try:
                        z = mg.req("leerlingen", kindid, "projecten", prj["Id"], "onderdelen", o["Id"], dict(gebruikMappenStructuur=True))
                        print(f"{z['Titel']}\n{dehtml(z['Omschrijving'])}")
                        for b in z["Bronnen"]:
                            uri = b["Uri"] or f"attachment: {b['ContentType']}"
                            print(f" - {b['Naam']} ; {uri}")
                    except urllib.error.HTTPError as e:
                        print(o['Titel'], e)

                print()

        print()

        #TODO self.req('personen', kindid, 'berichten') #  mapId=4   api/berichten/mappen/alle


if __name__ == '__main__':
    main()
