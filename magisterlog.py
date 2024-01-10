import os
import re
from collections import defaultdict

class Afspraak:
    def __init__(self, start, eind, soort, waar, vak_docent):
        self.start = start
        self.eind = eind
        self.soort = soort
        self.waar = waar
        self.vak_docent = vak_docent
        self.omschrijving = []
    def add(self, text):
        self.omschrijving.append(text)
    def tuple(self):
        return (self.start, self.eind, self.soort, self.waar, self.vak_docent, "\n".join(self.omschrijving))
    def __str__(self):
        return "%s ; %s ; %s ; %s ; %s ; %s" % (self.start, self.eind, self.soort, self.waar, self.vak_docent, "\t".join(self.omschrijving))

    def __eq__(lhs, rhs):
        return lhs.tuple() == rhs.tuple()
    def __hash__(self):
        return hash(self.tuple())

class Cijfer:
    def __init__(self, datumtijd, vak, cijfer, weging, toets):
        self.datumtijd = datumtijd
        self.vak = vak
        self.cijfer = cijfer
        self.weging = weging
        self.toets = toets
    def tuple(self):
        return (self.datumtijd, self.vak, self.cijfer, self.weging, self.toets)
    def __str__(self):
        return "%s ; %s ; %s ; %s ; %s" % (self.datumtijd, self.vak, self.cijfer, self.weging, self.toets)

    def __eq__(lhs, rhs):
        return lhs.tuple() == rhs.tuple()
    def __hash__(self):
        return hash(self.tuple())

class Voortgang:
    def __init__(self, toetsdatum, datumtijd, vak, cijfer, weging, groep, toets):
        self.toetsdatum = toetsdatum
        self.datumtijd = datumtijd
        self.vak = vak
        self.cijfer = cijfer
        self.weging = weging
        self.groep = groep
        self.toets = toets
    def tuple(self):
        return (self.toetsdatum, self.datumtijd, self.vak, self.cijfer, self.weging, self.groep, self.toets)
    def __str__(self):
        return "%s ; %s ; %s ; %s ; %s ; %s ; %s" % (self.toetsdatum, self.datumtijd, self.vak, self.cijfer, self.weging, self.groep, self.toets)
    def __eq__(lhs, rhs):
        return lhs.tuple() == rhs.tuple()
    def __hash__(self):
        return hash(self.tuple())

class Leerling:
    def __init__(self):
        self.studienummer = None
        self.naam = None
        self.geboren = None
        self.cijfers = []
        self.voortgang = []
        self.afspraken = []
        self.rooster = []
    def addsection(self, sectie, text):
        match sectie:
            case 'voortgang':
                self.process_voortgang(text)
            case 'cijfers':
                self.process_cijfers(text)
            case 'afspraken':
                self.process_afspraken(text)
            case 'roosterwijzigingen':
                self.process_rooster(text)
            case _:
                #print("negeer ", sectie)
                pass
    def process_voortgang(self, text):
        for line in text.split("\n"):
            if not line:
                pass
            elif m := re.match(r'^(.{10}) (\S+ \S+) - (\w+)\s+(\S+)\s+x\s+(?:k:)?(\S+) - (.*?) ; (.*)', line):
                self.voortgang.append(Voortgang(m[1], m[2], m[3], m[4], m[5], m[6], m[7]))
            else:
                print("?v", line)
        #print("v=", len(self.afspraken))

    def process_cijfers(self, text):
        for line in text.split("\n"):
            if not line:
                pass
            elif m := re.match(r'^(\S+ \S+) - (\w+)\s+(\S+)\s+x (\S+) - (.*)', line):
                self.cijfers.append(Cijfer(m[1], m[2], m[3], m[4], m[5]))
            else:
                print("?c", line)
        #print("c=", len(self.afspraken))
    def process_afspraken(self, text):
        for line in text.split("\n"):
            if not line:
                pass
            elif m := re.match(r'^(\S+ \S+) ; (\S+ \S+) <(..)> (.*?) ; (.*)', line):
                self.afspraken.append(Afspraak(m[1], m[2], m[3], m[4], m[5]))
            elif self.afspraken:
                self.afspraken[-1].add(line)
            else:
                print("?a", line)
                pass
        #print("a=", len(self.afspraken))

    def process_rooster(self, text):
        for line in text.split("\n"):
            if not line:
                pass
            elif m := re.match(r'^(\S+ \S+) ; (\S+ \S+) <(..)> (.*?) ; (.*)', line):
                self.rooster.append(Afspraak(m[1], m[2], m[3], m[4], m[5]))
            elif self.rooster:
                self.rooster[-1].add(line)
            else:
                print("?r", line)
                pass
        #print("r=", len(self.afspraken))


def readlog(fh):
    log = []
    leerling = None
    sectie = None
    text = None
    for line in fh:
        if m := re.match(r'\*+ (\d+) (.*?) \((\S+)\) \*+', line):
            #print("leerling %s" % m[2])
            if text:
                leerling.addsection(sectie, text)
            sectie = None
            text = None

            leerling = Leerling()
            leerling.studienummer, leerling.naam, leerling.geboren = m.groups()

            log.append(leerling)
        elif m := re.match(r'-- (.*?) --', line):
            if text:
                leerling.addsection(sectie, text)
            #print("sectie", sectie)
            sectie = m[1]
            text = ''
        elif m := re.match(r'-- (\w+wijzer.*?)', line):
            if text:
                leerling.addsection(sectie, text)
            #print("sectie", sectie)
            sectie = m[1]
            text = ''
        elif text is not None:
            #print("+ %d" % len(line))
            text += line
        else:
            #print("??", line)
            pass
    if text:
        leerling.addsection(sectie, text)

    #print("log done")
    return log

def main():
    lmap = defaultdict(list)
    import sys

    logpath = None
    if len(sys.argv)>1:
        logpath = sys.argv[1]
    else:
        for d in [os.getcwd(), sys.path[0]]:
            for lname in ['log', 'logs']:
                if os.path.exists(os.path.join(d, lname)):
                    logpath = os.path.join(d, lname)

    if not logpath:
        print("Can't find directory with magister logs. Please specify one on the commandline.")
        return
    for ent in os.scandir(logpath):
        if ent.is_file():
            try:
                with open(os.path.join(logpath, ent.name)) as fh:
                    log = readlog(fh)
                    for l in log:
                        l.logname = ent.name
                        lmap[l.studienummer].append(l)
            except Exception as e:
                print(f"ERROR {e} in {ent.name}")

    for l, ll in lmap.items():
        print("=== leerling %s === %d" % (l, len(ll)))
        voortgang = defaultdict(list)
        cijfers = defaultdict(list)
        afspraken = defaultdict(list)
        rooster = defaultdict(list)
        for ent in ll:
            for x in ent.voortgang:
                voortgang[x].append(ent.logname)
            for x in ent.cijfers:
                cijfers[x].append(ent.logname)
            for x in ent.afspraken:
                afspraken[x].append(ent.logname)
            for x in ent.rooster:
                rooster[x].append(ent.logname)
        print("-- voortgang --")
        for kv in sorted(voortgang.items(), key=lambda kv:min(kv[1])):
            print("%s - %s : %s" % (min(kv[1]), max(kv[1]), kv[0]))
        print("-- cijfers --")
        for kv in sorted(cijfers.items(), key=lambda kv:min(kv[1])):
            print("%s - %s : %s" % (min(kv[1]), max(kv[1]), kv[0]))
        print("-- afspraken --")
        for kv in sorted(afspraken.items(), key=lambda kv:min(kv[1])):
            print("%s - %s : %s" % (min(kv[1]), max(kv[1]), kv[0]))
        print("-- rooster --")
        for kv in sorted(rooster.items(), key=lambda kv:min(kv[1])):
            print("%s - %s : %s" % (min(kv[1]), max(kv[1]), kv[0]))

if __name__=='__main__':
    main()

