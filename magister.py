import re
import urllib.request
import urllib.parse
import http.cookiejar
import json

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

def datum(t):
    """
    Strip the date's to a more reasonable string.
    """
    if not t:
        return "?"
    return t[:19]


class Magister:
    """
    object encapsulating all magister functionality.
    """
    def __init__(self, args):
        self.args = args
        self.xsrftoken = None
        self.access_token = None
        self.magisterserver = args.magisterserver
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
        response = self.opener.open(req, **kwargs)
        data = response.read()
        if response.headers.get("content-type").find("application/json")>=0:
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
        if m := re.search(r'\(n=\["([0-9a-f",]+?)"\],\["([0-9",]+)"\]\.map', js):
            codes = m.group(1).split('","')
            idxes = [int(_) for _ in m.group(2).split('","')]

            return "".join(codes[_] for _ in idxes)
        
        print("Did not find encoded authcode, using default!")

        return self.args.authcode

    def extract_oidc_config(self, js, site):
        """
        Decode the javascript containing the oidc config.
        """
        cfg = dict()
        for line in js.split("\r\n"):
            if not line: continue
            if m := re.match(r'\s*(\w+):\s*(.*),?$', line):
                key, value = m.groups()
                value = re.sub(r'\' \+ window\.location\.hostname', f"{site}'", value)
                value = re.sub(r'\' \+ \'', "", value)
                if value == 'false':
                    value = False
                elif value == 'true':
                    value = True
                elif m := re.match(r'\'(.*)\',?$', value):
                    value = m.group(1)
                cfg[key] = value;

        return cfg

    def login(self, site, username, password):
        """
        Authenticate to the magister server for school 'site', using username and password.
        """
        openidcfg = self.httpreq(f"https://{self.magisterserver}/.well-known/openid-configuration")
        if not openidcfg:
            print("could not get magister openid config")
            return
        oidcjs = self.httpreq(f"https://{site}/oidc_config.js")
        if not oidcjs:
            print("could not get school config")
            return
        oidccfg = self.extract_oidc_config(oidcjs.decode('utf-8'), site)

        params = dict(
            client_id= oidccfg["client_id"],         # f"M6-{site}"
            redirect_uri= oidccfg["redirect_uri"],   # f"https://{site}/oidc/redirect_callback.html",
            response_type= oidccfg["response_type"], # "id_token token",
            scope= "openid profile",
            state= "11111111111111111111111111111111",
            nonce= "11111111111111111111111111111111",
            acr_values= oidccfg["acr_values"],       # f"tenant:{site}",
        )
        self.schoolserver = site

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
        # r.action == password
        # r.username = ...

        d["password"] = password

        self.logprint("\n---- password ----")
        r = self.httpreq(f"https://{self.magisterserver}/challenges/password", json.dumps(d))
        # r.action == null 
        # r.redirectURL= ...

        self.logprint("\n---- callback ----")
        url, html = self.httpredirurl(f"https://{self.magisterserver}" + r["redirectURL"])

        _, qs = url.split('#', 1)
        d = urllib.parse.parse_qs(qs)
        self.logprint(d)
        self.access_token = d["access_token"][0]

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
        return self.httpreq(f"https://{self.schoolserver}{link['href']}")


def printcijfers(c):
    print("-- cijfers --")
    for item in c["items"]:
        print("%s - %-3s %-6s x %3.1f - %s" % (datum(item["ingevoerdOp"]), item["vak"]["code"], item["waarde"], item["weegfactor"], item["omschrijving"]))

def printvoortgang(v):
    print("-- voortgang --")
    for item in v["items"]:
        print("%s - %-8s %-6s x %3.1f - %s" % (datum(item["ingevoerdOp"]), item["kolom"]["naam"], item["waarde"], item["kolom"]["weegfactor"], item["kolom"]["omschrijving"]))

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

def printafspraken(x):
    print("-- afspraken --")
    for item in x["Items"]:
        print("%s ; %s - %s ; %s" % (datum(item["Start"]), datum(item["Einde"]), item["Lokatie"], item["Omschrijving"]))
        if item["Inhoud"]:
            print(dehtml(item["Inhoud"]))

def printwijzigingen(x):
    print("-- roosterwijzigingen --")
    for item in x["Items"]:
        print("%s ; %s - %s ; %s" % (datum(item["Start"]), datum(item["Einde"]), item["Lokatie"], item["Omschrijving"]))
        if item["Inhoud"]:
            print(dehtml(item["Inhoud"]))

def printstudiewijzer(x):
    print("-- studiewijzer %s - %s ; %s" % (datum(x["Van"]), datum(x["TotEnMet"]), x["Titel"]))


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


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Magister info dump')
    parser.add_argument('--debug', '-d', action='store_true', help='print all intermediate steps')
    parser.add_argument('--all', '-a', action='store_true', help='output all info')
    parser.add_argument('--cijfers', '-c', action='store_true', help='output cijfers')
    parser.add_argument('--rooster', '-r', action='store_true', help='output rooster')
    parser.add_argument('--absenties', '-A', action='store_true', help='output absenties')
    parser.add_argument('--studiewijzer', '-s', action='store_true', help='output studiewijzer')
    parser.add_argument('--config', help='specify configuration file.')
    parser.add_argument('--verbose', action='store_true')
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

    if not args.config:
        import os
        homedir = os.environ['HOME']
        args.config = os.path.join(homedir, ".magisterrc")

    try:
        cfg = loadconfig(args.config)

        applyconfig(cfg, args)
    except Exception as e:
        print("config: %s" % e)

    mg = Magister(args)
    if not mg.login(args.schoolserver, args.username, args.password):
        print("Login failed")
        return

    d = mg.req("account")
    ouderid = d["Persoon"]["Id"]

    k = mg.req("personen", ouderid, "kinderen")

    for kind in k["Items"]:
        print(f"****** {kind['Stamnummer']} {kind['Roepnaam']} {kind['Achternaam']} ({kind['Geboortedatum']}) ******")
        kindid = kind["Id"]
        x = mg.req("personen", kindid, "aanmeldingen")
        printaanmeldingen(x)

        if args.cijfers:
            c = mg.req("personen", kindid, "cijfers", "laatste", dict(top=50))
            printcijfers(c)
            if c["links"].get("voortgangscijfers"):
                v = mg.getlink(c["links"]["voortgangscijfers"])
                print("-- voortgang --")
                printvoortgang(v)

        x = mg.req("personen", kindid, "opdrachten")
        printopdrachten(x)

        x = mg.req("leerlingen", kindid, "projecten")
        printprojecten(x)

        x = mg.req("personen", kindid, "activiteiten")
        printactiviteiten(x)

        if args.absenties:
            x = mg.req("personen", kindid, "absentieperioden")
            print("ap:", x)
            x = mg.req("personen", kindid, "absenties", dict(van="2016-01-01", tot="2026-01-01"))
            printabsenties(x)

        if args.rooster:
            x = mg.req("personen", kindid, "afspraken")
            printafspraken(x)

            x = mg.req("personen", kindid, "roosterwijzigingen")
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

        print()

        #TODO self.req('personen', kindid, 'berichten') #  mapId=4   api/berichten/mappen/alle


if __name__ == '__main__':
    main()
